//===-- SanitizerCoverage.cpp - coverage instrumentation for sanitizers ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Coverage instrumentation done on LLVM IR level, works with Sanitizers.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Instrumentation/SanitizerCoverage.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#if LLVM_VERSION_MAJOR >= 15
  #if LLVM_VERSION_MAJOR < 17
    #include "llvm/ADT/Triple.h"
  #endif
#endif
#include "llvm/Analysis/PostDominators.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/IR/CFG.h"
#endif
#include "llvm/IR/Constant.h"
#include "llvm/IR/DataLayout.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/IR/DebugInfo.h"
#endif
#include "llvm/IR/Dominators.h"
#if LLVM_VERSION_MAJOR >= 17
  #include "llvm/IR/EHPersonalities.h"
#else
  #include "llvm/Analysis/EHPersonalities.h"
#endif
#include "llvm/IR/Function.h"
#if LLVM_VERSION_MAJOR >= 16
  #include "llvm/IR/GlobalVariable.h"
#endif
#include "llvm/IR/IRBuilder.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/IR/InlineAsm.h"
#endif
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/IR/MDBuilder.h"
  #include "llvm/IR/Mangler.h"
#endif
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/Type.h"
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/InitializePasses.h"
#endif
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/VirtualFileSystem.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/Support/raw_ostream.h"
#endif
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/Transforms/Instrumentation.h"
#else
  #include "llvm/TargetParser/Triple.h"
#endif
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "config.h"
#include "debug.h"
#include "afl-llvm-common.h"

//HorseFuzz
#include <sys/stat.h>
#include <errno.h>
#include <cstring>
#include <iostream>
#include <algorithm> // for sort
#include <utility>   // for std::pair

typedef struct hashset_st {
  size_t nbits;
  size_t capacity;
  size_t mask;
  size_t nitems;
  size_t n_deleted_items;
  unsigned long *items;
} *hashset_t;

static const unsigned int prime_1 = 73;
static const unsigned int prime_2 = 5009;

hashset_t hashset_create();
size_t hashset_num_items(hashset_t set);
void hashset_destroy(hashset_t set);
int hashset_add(hashset_t set, void *item);
int hashset_remove(hashset_t set, void *item);
int hashset_is_member(hashset_t set, void *item);
uint32_t hash32(const void *key, size_t length, uint32_t seed);

using namespace llvm;

#define DEBUG_TYPE "sancov"

static const uint64_t SanCtorAndDtorPriority = 2;

const char SanCovTracePCName[] = "__sanitizer_cov_trace_pc";
const char SanCovTraceCmp1[] = "__sanitizer_cov_trace_cmp1";
const char SanCovTraceCmp2[] = "__sanitizer_cov_trace_cmp2";
const char SanCovTraceCmp4[] = "__sanitizer_cov_trace_cmp4";
const char SanCovTraceCmp8[] = "__sanitizer_cov_trace_cmp8";
const char SanCovTraceConstCmp1[] = "__sanitizer_cov_trace_const_cmp1";
const char SanCovTraceConstCmp2[] = "__sanitizer_cov_trace_const_cmp2";
const char SanCovTraceConstCmp4[] = "__sanitizer_cov_trace_const_cmp4";
const char SanCovTraceConstCmp8[] = "__sanitizer_cov_trace_const_cmp8";
const char SanCovTraceSwitchName[] = "__sanitizer_cov_trace_switch";

const char SanCovModuleCtorTracePcGuardName[] =
    "sancov.module_ctor_trace_pc_guard";
const char SanCovTracePCGuardInitName[] = "__sanitizer_cov_trace_pc_guard_init";

const char SanCovTracePCGuardName[] = "__sanitizer_cov_trace_pc_guard";

const char SanCovGuardsSectionName[] = "sancov_guards";
const char SanCovCountersSectionName[] = "sancov_cntrs";
const char SanCovBoolFlagSectionName[] = "sancov_bools";
const char SanCovPCsSectionName[] = "sancov_pcs";

const char SanCovLowestStackName[] = "__sancov_lowest_stack";

static const char *skip_nozero;
static const char *use_threadsafe_counters;

namespace {

SanitizerCoverageOptions OverrideFromCL(SanitizerCoverageOptions Options) {

  Options.CoverageType = SanitizerCoverageOptions::SCK_Edge;
  // Options.NoPrune = true;
  Options.TracePCGuard = true;  // TracePCGuard is default.
  return Options;

}

using DomTreeCallback = function_ref<const DominatorTree *(Function &F)>;
using PostDomTreeCallback =
    function_ref<const PostDominatorTree *(Function &F)>;

class ModuleSanitizerCoverageAFL
    : public PassInfoMixin<ModuleSanitizerCoverageAFL> {

 public:
  ModuleSanitizerCoverageAFL(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions())
      : Options(OverrideFromCL(Options)) {

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  bool              instrumentModule(Module &M, DomTreeCallback DTCallback,
                                     PostDomTreeCallback PDTCallback);

 private:
  void instrumentFunction(Function &F, Module &M, LLVMContext &C, const std::string &file_name,
                          DomTreeCallback DTCallback,
                          PostDomTreeCallback PDTCallback,
                          std::map<std::string, int> &fb);
  void InjectTraceForCmp(Function &F, ArrayRef<Instruction *> CmpTraceTargets);
  void InjectTraceForSwitch(Function               &F,
                            ArrayRef<Instruction *> SwitchTraceTargets);
  bool InjectCoverage(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                      bool IsLeafFunc = true);
  GlobalVariable *CreateFunctionLocalArrayInSection(size_t    NumElements,
                                                    Function &F, Type *Ty,
                                                    const char *Section);
  GlobalVariable *CreatePCArray(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void CreateFunctionLocalArrays(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                                 uint32_t special);
  void InjectCoverageAtBlock(Function &F, BasicBlock &BB, size_t Idx,
                             bool IsLeafFunc = true);
  Function *CreateInitCallsForSections(Module &M, const char *CtorName,
                                       const char *InitFunctionName, Type *Ty,
                                       const char *Section);
  std::pair<Value *, Value *> CreateSecStartEnd(Module &M, const char *Section,
                                                Type *Ty);

  void SetNoSanitizeMetadata(Instruction *I) {

#if LLVM_VERSION_MAJOR >= 19
    I->setNoSanitizeMetadata();
#elif LLVM_VERSION_MAJOR >= 16
    I->setMetadata(LLVMContext::MD_nosanitize, MDNode::get(*C, std::nullopt));
#else
    I->setMetadata(I->getModule()->getMDKindID("nosanitize"),
                   MDNode::get(*C, None));
#endif

  }

  std::string     getSectionName(const std::string &Section) const;
  std::string     getSectionStart(const std::string &Section) const;
  std::string     getSectionEnd(const std::string &Section) const;
  FunctionCallee  SanCovTracePC, SanCovTracePCGuard;
  FunctionCallee  SanCovTraceCmpFunction[4];
  FunctionCallee  SanCovTraceConstCmpFunction[4];
  FunctionCallee  SanCovTraceSwitchFunction;
  GlobalVariable *SanCovLowestStack;
  Type *IntptrTy, *IntptrPtrTy, *Int64Ty, *Int64PtrTy, *Int32Ty, *Int32PtrTy,
      *Int16Ty, *Int8Ty, *Int8PtrTy, *Int1Ty, *Int1PtrTy, *PtrTy;
  Module           *CurModule;
  std::string       CurModuleUniqueId;
  Triple            TargetTriple;
  LLVMContext      *C;
  const DataLayout *DL;

  GlobalVariable *FunctionGuardArray;        // for trace-pc-guard.
  GlobalVariable *Function8bitCounterArray;  // for inline-8bit-counters.
  GlobalVariable *FunctionBoolArray;         // for inline-bool-flag.
  GlobalVariable *FunctionPCsArray;          // for pc-table.
  SmallVector<GlobalValue *, 20> GlobalsToAppendToUsed;
  SmallVector<GlobalValue *, 20> GlobalsToAppendToCompilerUsed;

  // HorseFuzz
  // Define global variables for logging
  hashset_t funcSet = hashset_create();
  std::ofstream outfile;
  std::ofstream outfile1;

  SanitizerCoverageOptions Options;

  uint32_t        instr = 0, selects = 0, unhandled = 0, dump_cc = 0;
  GlobalVariable *AFLMapPtr = NULL;
  ConstantInt    *One = NULL;
  ConstantInt    *Zero = NULL;
};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "SanitizerCoveragePCGUARD", "v0.2",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

#if LLVM_VERSION_MAJOR == 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
#if LLVM_VERSION_MAJOR >= 16
            PB.registerOptimizerEarlyEPCallback(
#else
            PB.registerOptimizerLastEPCallback(
#endif
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(ModuleSanitizerCoverageAFL());

                });

          }};

}

PreservedAnalyses ModuleSanitizerCoverageAFL::run(Module                &M,
                                                  ModuleAnalysisManager &MAM) {

  ModuleSanitizerCoverageAFL ModuleSancov(Options);
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto  DTCallback = [&FAM](Function &F) -> const DominatorTree  *{

    return &FAM.getResult<DominatorTreeAnalysis>(F);

  };

  auto PDTCallback = [&FAM](Function &F) -> const PostDominatorTree * {

    return &FAM.getResult<PostDominatorTreeAnalysis>(F);

  };

  if (ModuleSancov.instrumentModule(M, DTCallback, PDTCallback))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();

}

std::pair<Value *, Value *> ModuleSanitizerCoverageAFL::CreateSecStartEnd(
    Module &M, const char *Section, Type *Ty) {

  // Use ExternalWeak so that if all sections are discarded due to section
  // garbage collection, the linker will not report undefined symbol errors.
  // Windows defines the start/stop symbols in compiler-rt so no need for
  // ExternalWeak.
  GlobalValue::LinkageTypes Linkage = TargetTriple.isOSBinFormatCOFF()
                                          ? GlobalVariable::ExternalLinkage
                                          : GlobalVariable::ExternalWeakLinkage;
  GlobalVariable *SecStart = new GlobalVariable(M, Ty, false, Linkage, nullptr,
                                                getSectionStart(Section));
  SecStart->setVisibility(GlobalValue::HiddenVisibility);
  GlobalVariable *SecEnd = new GlobalVariable(M, Ty, false, Linkage, nullptr,
                                              getSectionEnd(Section));
  SecEnd->setVisibility(GlobalValue::HiddenVisibility);
  IRBuilder<> IRB(M.getContext());
  if (!TargetTriple.isOSBinFormatCOFF())
    return std::make_pair(SecStart, SecEnd);

    // Account for the fact that on windows-msvc __start_* symbols actually
    // point to a uint64_t before the start of the array.
#if LLVM_VERSION_MAJOR >= 19
  auto GEP =
      IRB.CreatePtrAdd(SecStart, ConstantInt::get(IntptrTy, sizeof(uint64_t)));
  return std::make_pair(GEP, SecEnd);
#else
  auto SecStartI8Ptr = IRB.CreatePointerCast(SecStart, Int8PtrTy);
  auto GEP = IRB.CreateGEP(Int8Ty, SecStartI8Ptr,
                           ConstantInt::get(IntptrTy, sizeof(uint64_t)));
  return std::make_pair(IRB.CreatePointerCast(GEP, PointerType::getUnqual(Ty)),
                        SecEnd);
#endif

}

Function *ModuleSanitizerCoverageAFL::CreateInitCallsForSections(
    Module &M, const char *CtorName, const char *InitFunctionName, Type *Ty,
    const char *Section) {

  auto      SecStartEnd = CreateSecStartEnd(M, Section, Ty);
  auto      SecStart = SecStartEnd.first;
  auto      SecEnd = SecStartEnd.second;
  Function *CtorFunc;
  Type     *PtrTy = PointerType::getUnqual(Ty);
  std::tie(CtorFunc, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, CtorName, InitFunctionName, {PtrTy, PtrTy}, {SecStart, SecEnd});
  assert(CtorFunc->getName() == CtorName);

  if (TargetTriple.supportsCOMDAT()) {

    // Use comdat to dedup CtorFunc.
    CtorFunc->setComdat(M.getOrInsertComdat(CtorName));
    appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority, CtorFunc);

  } else {

    appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority);

  }

  if (TargetTriple.isOSBinFormatCOFF()) {

    // In COFF files, if the contructors are set as COMDAT (they are because
    // COFF supports COMDAT) and the linker flag /OPT:REF (strip unreferenced
    // functions and data) is used, the constructors get stripped. To prevent
    // this, give the constructors weak ODR linkage and ensure the linker knows
    // to include the sancov constructor. This way the linker can deduplicate
    // the constructors but always leave one copy.
    CtorFunc->setLinkage(GlobalValue::WeakODRLinkage);

  }

  return CtorFunc;

}

// HorseFuzz: sort
bool sortByVal(const std::pair<std::string, int> &a, const std::pair<std::string, int> &b) {
  return (a.second < b.second);
}

bool ModuleSanitizerCoverageAFL::instrumentModule(
    Module &M, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  setvbuf(stdout, NULL, _IONBF, 0);

  if (getenv("AFL_DEBUG")) { debug = 1; }

  if (getenv("AFL_DUMP_CYCLOMATIC_COMPLEXITY")) { dump_cc = 1; }

  if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {

    SAYF(cCYA "SanitizerCoveragePCGUARD" VERSION cRST "\n");

  } else {

    be_quiet = 1;

  }

  skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");
  use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");

  initInstrumentList();
  scanForDangerousFunctions(&M);

  C = &(M.getContext());
  DL = &M.getDataLayout();
  CurModule = &M;
  CurModuleUniqueId = getUniqueModuleId(CurModule);
  TargetTriple = Triple(M.getTargetTriple());
  FunctionGuardArray = nullptr;
  Function8bitCounterArray = nullptr;
  FunctionBoolArray = nullptr;
  FunctionPCsArray = nullptr;
  IntptrTy = Type::getIntNTy(*C, DL->getPointerSizeInBits());
  IntptrPtrTy = PointerType::getUnqual(IntptrTy);
  Type       *VoidTy = Type::getVoidTy(*C);
  IRBuilder<> IRB(*C);
  Int64PtrTy = PointerType::getUnqual(IRB.getInt64Ty());
  Int32PtrTy = PointerType::getUnqual(IRB.getInt32Ty());
  Int8PtrTy = PointerType::getUnqual(IRB.getInt8Ty());
  Int1PtrTy = PointerType::getUnqual(IRB.getInt1Ty());
  Int64Ty = IRB.getInt64Ty();
  Int32Ty = IRB.getInt32Ty();
  Int16Ty = IRB.getInt16Ty();
  Int8Ty = IRB.getInt8Ty();
  Int1Ty = IRB.getInt1Ty();
  PtrTy = PointerType::getUnqual(*C);

  LLVMContext &Ctx = M.getContext();
  AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
  One = ConstantInt::get(IntegerType::getInt8Ty(Ctx), 1);
  Zero = ConstantInt::get(IntegerType::getInt8Ty(Ctx), 0);

  // Make sure smaller parameters are zero-extended to i64 if required by the
  // target ABI.
  AttributeList SanCovTraceCmpZeroExtAL;
  SanCovTraceCmpZeroExtAL =
      SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 0, Attribute::ZExt);
  SanCovTraceCmpZeroExtAL =
      SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 1, Attribute::ZExt);

  SanCovTraceCmpFunction[0] =
      M.getOrInsertFunction(SanCovTraceCmp1, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt8Ty(), IRB.getInt8Ty());
  SanCovTraceCmpFunction[1] =
      M.getOrInsertFunction(SanCovTraceCmp2, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt16Ty(), IRB.getInt16Ty());
  SanCovTraceCmpFunction[2] =
      M.getOrInsertFunction(SanCovTraceCmp4, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt32Ty(), IRB.getInt32Ty());
  SanCovTraceCmpFunction[3] =
      M.getOrInsertFunction(SanCovTraceCmp8, VoidTy, Int64Ty, Int64Ty);

  SanCovTraceConstCmpFunction[0] = M.getOrInsertFunction(
      SanCovTraceConstCmp1, SanCovTraceCmpZeroExtAL, VoidTy, Int8Ty, Int8Ty);
  SanCovTraceConstCmpFunction[1] = M.getOrInsertFunction(
      SanCovTraceConstCmp2, SanCovTraceCmpZeroExtAL, VoidTy, Int16Ty, Int16Ty);
  SanCovTraceConstCmpFunction[2] = M.getOrInsertFunction(
      SanCovTraceConstCmp4, SanCovTraceCmpZeroExtAL, VoidTy, Int32Ty, Int32Ty);
  SanCovTraceConstCmpFunction[3] =
      M.getOrInsertFunction(SanCovTraceConstCmp8, VoidTy, Int64Ty, Int64Ty);

  SanCovTraceSwitchFunction =
      M.getOrInsertFunction(SanCovTraceSwitchName, VoidTy, Int64Ty, Int64PtrTy);

  Constant *SanCovLowestStackConstant =
      M.getOrInsertGlobal(SanCovLowestStackName, IntptrTy);
  SanCovLowestStack = dyn_cast<GlobalVariable>(SanCovLowestStackConstant);
  if (!SanCovLowestStack || SanCovLowestStack->getValueType() != IntptrTy) {

    C->emitError(StringRef("'") + SanCovLowestStackName +
                 "' should not be declared by the user");
    return true;

  }

  SanCovLowestStack->setThreadLocalMode(
      GlobalValue::ThreadLocalMode::InitialExecTLSModel);

  SanCovTracePC = M.getOrInsertFunction(SanCovTracePCName, VoidTy);
  SanCovTracePCGuard =
      M.getOrInsertFunction(SanCovTracePCGuardName, VoidTy, Int32PtrTy);

  // HorseFuzz: parse file name
  std::string module_str(M.getName().data());
  std::size_t found = module_str.find_last_of("/\\");
  std::string file_name = module_str.substr(found+1);
  // // SAYF("Module: %s, file name: %s\n", module_str.c_str(), file_name.c_str());

  const char* binary_env = getenv("HF_BINARY");

  // Check if the environment variable is set
  if (binary_env != nullptr) {
    std::string binary(binary_env);
    std::string tmp_dir = "/tmp/" + binary;
    std::string fn_funcs = tmp_dir + "/func_ids.log";
    std::string fn_bbs = tmp_dir + "/func_bbs.log";

    // Ensure the directory exists
    if (mkdir(tmp_dir.c_str(), 0700) && errno != EEXIST) {
      perror("Unable to create directory");
      exit(1);
    }

    outfile.open(fn_funcs.c_str(), std::ofstream::out | std::ofstream::app);
    outfile1.open(fn_bbs.c_str(), std::ofstream::out | std::ofstream::app);
  }


  LLVMContext &C = M.getContext();
  std::map<std::string,int> fb;

  for (auto &F : M)
    instrumentFunction(F, M, C, file_name, DTCallback, PDTCallback, fb);

  Function *Ctor = nullptr;

  if (FunctionGuardArray)
    Ctor = CreateInitCallsForSections(M, SanCovModuleCtorTracePcGuardName,
                                      SanCovTracePCGuardInitName, Int32PtrTy,
                                      SanCovGuardsSectionName);

  if (Ctor && debug) {

    fprintf(stderr, "SANCOV: installed pcguard_init in ctor\n");

  }

  appendToUsed(M, GlobalsToAppendToUsed);
  appendToCompilerUsed(M, GlobalsToAppendToCompilerUsed);

  if (binary_env != nullptr) {
    // Sort functions based on their number of basic blocks
    std::vector<std::pair<std::string, int>> vec;
    std::map<std::string, int>::iterator it2;
    for (it2 = fb.begin(); it2 != fb.end(); it2++)
      vec.push_back(make_pair(it2->first, it2->second));
    std::sort(vec.begin(), vec.end(), sortByVal);
    for (int i = 0; i < (int) vec.size(); i++)
      outfile1 << vec[i].first.c_str() << ": " << vec[i].second << "\n";

    outfile.close();
    outfile1.close();
  }

  if (!be_quiet) {

    if (!instr) {

      WARNF("No instrumentation targets found.");

    } else {

      char modeline[128];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_TSAN") ? ", TSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      OKF("Instrumented %u locations with no collisions (%s mode) of which are "
          "%u handled and %u unhandled selects.",
          instr, modeline, selects, unhandled);

    }

  }

  return true;

}

// True if block has successors and it dominates all of them.
static bool isFullDominator(const BasicBlock *BB, const DominatorTree *DT) {

  if (succ_empty(BB)) return false;

  return llvm::all_of(successors(BB), [&](const BasicBlock *SUCC) {

    return DT->dominates(BB, SUCC);

  });

}

// True if block has predecessors and it postdominates all of them.
static bool isFullPostDominator(const BasicBlock        *BB,
                                const PostDominatorTree *PDT) {

  if (pred_empty(BB)) return false;

  return llvm::all_of(predecessors(BB), [&](const BasicBlock *PRED) {

    return PDT->dominates(BB, PRED);

  });

}

static bool shouldInstrumentBlock(const Function &F, const BasicBlock *BB,
                                  const DominatorTree            *DT,
                                  const PostDominatorTree        *PDT,
                                  const SanitizerCoverageOptions &Options) {

  // Don't insert coverage for blocks containing nothing but unreachable: we
  // will never call __sanitizer_cov() for them, so counting them in
  // NumberOfInstrumentedBlocks() might complicate calculation of code coverage
  // percentage. Also, unreachable instructions frequently have no debug
  // locations.
  if (isa<UnreachableInst>(BB->getFirstNonPHIOrDbgOrLifetime())) return false;

  // Don't insert coverage into blocks without a valid insertion point
  // (catchswitch blocks).
  if (BB->getFirstInsertionPt() == BB->end()) return false;

  if (Options.NoPrune || &F.getEntryBlock() == BB) return true;

  // Do not instrument full dominators, or full post-dominators with multiple
  // predecessors.
  return !isFullDominator(BB, DT) &&
         !(isFullPostDominator(BB, PDT) && !BB->getSinglePredecessor());

}

// Returns true iff From->To is a backedge.
// A twist here is that we treat From->To as a backedge if
//   * To dominates From or
//   * To->UniqueSuccessor dominates From
#if 0
static bool IsBackEdge(BasicBlock *From, BasicBlock *To,
                       const DominatorTree *DT) {

  if (DT->dominates(To, From))
    return true;
  if (auto Next = To->getUniqueSuccessor())
    if (DT->dominates(Next, From))
      return true;
  return false;

}

#endif

// Prunes uninteresting Cmp instrumentation:
//   * CMP instructions that feed into loop backedge branch.
//
// Note that Cmp pruning is controlled by the same flag as the
// BB pruning.
#if 0
static bool IsInterestingCmp(ICmpInst *CMP, const DominatorTree *DT,
                             const SanitizerCoverageOptions &Options) {

  if (!Options.NoPrune)
    if (CMP->hasOneUse())
      if (auto BR = dyn_cast<BranchInst>(CMP->user_back()))
        for (BasicBlock *B : BR->successors())
          if (IsBackEdge(BR->getParent(), B, DT))
            return false;
  return true;

}

#endif

void ModuleSanitizerCoverageAFL::instrumentFunction(
    Function &F, Module &M, LLVMContext &C, const std::string &file_name, 
    DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback, std::map<std::string, int> &fb) {

  if (F.empty()) return;
  if (!isInInstrumentList(&F, FMNAME)) return;
  // if (F.getName().find(".module_ctor") != std::string::npos)
  if (F.getName().contains(".module_ctor"))
    return;  // Should not instrument sanitizer init functions.
#if LLVM_VERSION_MAJOR >= 18
  if (F.getName().starts_with("__sanitizer_"))
#else
  if (F.getName().startswith("__sanitizer_"))
#endif
    return;  // Don't instrument __sanitizer_* callbacks.
  // Don't touch available_externally functions, their actual body is elewhere.
  if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage) return;
  // Don't instrument MSVC CRT configuration helpers. They may run before normal
  // initialization.
  if (F.getName() == "__local_stdio_printf_options" ||
      F.getName() == "__local_stdio_scanf_options")
    return;
  if (isa<UnreachableInst>(F.getEntryBlock().getTerminator())) return;
  // Don't instrument functions using SEH for now. Splitting basic blocks like
  // we do for coverage breaks WinEHPrepare.
  // FIXME: Remove this when SEH no longer uses landingpad pattern matching.
  if (F.hasPersonalityFn() &&
      isAsynchronousEHPersonality(classifyEHPersonality(F.getPersonalityFn())))
    return;
  if (F.hasFnAttribute(Attribute::NoSanitizeCoverage)) return;
#if LLVM_VERSION_MAJOR >= 19
  if (F.hasFnAttribute(Attribute::DisableSanitizerInstrumentation)) return;
#endif
  if (Options.CoverageType >= SanitizerCoverageOptions::SCK_Edge)
    SplitAllCriticalEdges(
        F, CriticalEdgeSplittingOptions().setIgnoreUnreachableDests());
  SmallVector<BasicBlock *, 16> BlocksToInstrument;
  SmallVector<Instruction *, 8> CmpTraceTargets;
  SmallVector<Instruction *, 8> SwitchTraceTargets;

  const DominatorTree     *DT = DTCallback(F);
  const PostDominatorTree *PDT = PDTCallback(F);
  bool                     IsLeafFunc = true;

  // HorseFuzz
  int nb_indirected_calls = 0;

  std::string funcName = F.getName().str();
  std::string fileFuncName = file_name + ":" + funcName;

  // HorseFuzz: write function name & hash value to file
  int cnt_bbs = 0;
  size_t cksum = (size_t) hash32(fileFuncName.c_str(), strlen(fileFuncName.c_str()), 0xa5b35705);

  for (auto &BB : F) {

    if (shouldInstrumentBlock(F, &BB, DT, PDT, Options))
      BlocksToInstrument.push_back(&BB);
    /*
        for (auto &Inst : BB) {

          if (Options.TraceCmp) {

            if (ICmpInst *CMP = dyn_cast<ICmpInst>(&Inst))
              if (IsInterestingCmp(CMP, DT, Options))
                CmpTraceTargets.push_back(&Inst);
            if (isa<SwitchInst>(&Inst))
              SwitchTraceTargets.push_back(&Inst);

          }

        }

    */
    if (getenv("HORSEFUZZ_CG_PROFILING")) {
      // if (debug) {
      //     fprintf(stderr, "HORSEFUZZ_CG_PROFILING is enabled, inspecting instructions in Basic Block\n");
      // }
      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));

      for (auto Inst = BB.begin(); Inst != BB.end(); Inst++) {
        Instruction &inst = *Inst;

        if (CallInst* callInst = dyn_cast<CallInst>(&inst)) {
          Function* fcallee = callInst->getCalledFunction();
          if (fcallee != NULL){
            std::string callee = fcallee->getName().str();
            if (callee.compare(0, 5, "llvm.") == 0)
              continue;
            // HorseFuzz: call the profiling covered functions
            if (debug) {
              fprintf(stderr, "Profiling function call in file: %s, function: %s -> %s\n",
                      file_name.c_str(), F.getName().str().c_str(), callee.c_str());
            }
            Value *callerName = IRB.CreateGlobalStringPtr(fileFuncName);
            Value *calleeName = IRB.CreateGlobalStringPtr(callee);
            Type *Args[] = {
              Type::getInt8PtrTy(C), // uint8_t *caller
              Type::getInt8PtrTy(C), // uint8_t *callee
            };
            FunctionType *FTy = FunctionType::get(Type::getVoidTy(C), Args, false);
            llvm::FunctionCallee funcProfil = M.getOrInsertFunction("llvm_profiling_fcov", FTy);
            IRB.CreateCall(funcProfil, {callerName, calleeName});
          } else {
            // Handle indirect calls
            Value* v = callInst->getCalledOperand();
            Value* sv = v->stripPointerCasts();

            if (Function* calleeFunc = dyn_cast<Function>(sv)) {
                // Resolved indirect call
                StringRef fname = calleeFunc->getName();
                Value *callerName = IRB.CreateGlobalStringPtr(fileFuncName);
                Value* calleeName = IRB.CreateGlobalStringPtr(fname.str());
                Type *Args[] = {
                  Type::getInt8PtrTy(C), // uint8_t *caller
                  Type::getInt8PtrTy(C), // uint8_t *callee
                };
                FunctionType *FTy = FunctionType::get(Type::getVoidTy(C), Args, false);
                llvm::FunctionCallee funcProfil = M.getOrInsertFunction("llvm_profiling_fcov", FTy);
                IRB.CreateCall(funcProfil, {callerName, calleeName});
                if (debug) {
                    fprintf(stderr, "######### Indirect call resolved to function: %s in file: %s, function: %s\n",
                            fname.str().c_str(),
                            file_name.c_str(),
                            F.getName().str().c_str());
                }
            } else if (debug) {
                // Do nothing for unresolved calls, optionally log for debugging
                fprintf(stderr, "### Indirect call to unresolved function in file: %s, function: %s\n",
                        file_name.c_str(),
                        F.getName().str().c_str());
            }


            nb_indirected_calls++;
          }
        }

        // Clear up profiling at return of the main function
        if (funcName.compare("main") == 0 && isa<ReturnInst>(&inst)) {
          FunctionType *FTy = FunctionType::get(Type::getVoidTy(C), false);
          llvm::FunctionCallee funcProfil = M.getOrInsertFunction("llvm_profiling_finish", FTy);
          IRB.CreateCall(funcProfil);
        }
      }
    }
    cnt_bbs++;

  }

  // HorseFuzz: print information here so that F has some basic blocks
  if(!hashset_is_member(funcSet, (void*) cksum)) {
    // SAYF("new fileFuncName: %s, hash value: %u\n", fileFuncName.c_str(), cksum);
    hashset_add(funcSet, (void*) cksum);
    // TODO: remove redundant lines
    outfile << fileFuncName.c_str() << " " << cksum << "\n";
  }

  if (debug) {

    fprintf(stderr, "SanitizerCoveragePCGUARD: instrumenting %s in %s\n",
            F.getName().str().c_str(), F.getParent()->getName().str().c_str());

  }

  InjectCoverage(F, BlocksToInstrument, IsLeafFunc);
  // InjectTraceForCmp(F, CmpTraceTargets);
  // InjectTraceForSwitch(F, SwitchTraceTargets);

  fb[fileFuncName] = cnt_bbs;

  if (dump_cc) { calcCyclomaticComplexity(&F); }

}

GlobalVariable *ModuleSanitizerCoverageAFL::CreateFunctionLocalArrayInSection(
    size_t NumElements, Function &F, Type *Ty, const char *Section) {

  ArrayType *ArrayTy = ArrayType::get(Ty, NumElements);
  auto       Array = new GlobalVariable(
      *CurModule, ArrayTy, false, GlobalVariable::PrivateLinkage,
      Constant::getNullValue(ArrayTy), "__sancov_gen_");

  if (TargetTriple.supportsCOMDAT() &&
      (TargetTriple.isOSBinFormatELF() || !F.isInterposable()))
    if (auto Comdat = getOrCreateFunctionComdat(F, TargetTriple))
      Array->setComdat(Comdat);
  Array->setSection(getSectionName(Section));
#if LLVM_VERSION_MAJOR >= 16
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedValue()));
#else
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedSize()));
#endif

  // sancov_pcs parallels the other metadata section(s). Optimizers (e.g.
  // GlobalOpt/ConstantMerge) may not discard sancov_pcs and the other
  // section(s) as a unit, so we conservatively retain all unconditionally in
  // the compiler.
  //
  // With comdat (COFF/ELF), the linker can guarantee the associated sections
  // will be retained or discarded as a unit, so llvm.compiler.used is
  // sufficient. Otherwise, conservatively make all of them retained by the
  // linker.
  if (Array->hasComdat())
    GlobalsToAppendToCompilerUsed.push_back(Array);
  else
    GlobalsToAppendToUsed.push_back(Array);

  return Array;

}

GlobalVariable *ModuleSanitizerCoverageAFL::CreatePCArray(
    Function &F, ArrayRef<BasicBlock *> AllBlocks) {

  size_t N = AllBlocks.size();
  assert(N);
  SmallVector<Constant *, 32> PCs;
  IRBuilder<>                 IRB(&*F.getEntryBlock().getFirstInsertionPt());
  for (size_t i = 0; i < N; i++) {

    if (&F.getEntryBlock() == AllBlocks[i]) {

      PCs.push_back((Constant *)IRB.CreatePointerCast(&F, PtrTy));
      PCs.push_back(
          (Constant *)IRB.CreateIntToPtr(ConstantInt::get(IntptrTy, 1), PtrTy));

    } else {

      PCs.push_back((Constant *)IRB.CreatePointerCast(
          BlockAddress::get(AllBlocks[i]), PtrTy));
#if LLVM_VERSION_MAJOR >= 16
      PCs.push_back(Constant::getNullValue(PtrTy));
#else
      PCs.push_back((Constant *)IRB.CreateIntToPtr(
          ConstantInt::get(IntptrTy, 0), IntptrPtrTy));
#endif

    }

  }

  auto *PCArray =
      CreateFunctionLocalArrayInSection(N * 2, F, PtrTy, SanCovPCsSectionName);
  PCArray->setInitializer(
      ConstantArray::get(ArrayType::get(PtrTy, N * 2), PCs));
  PCArray->setConstant(true);

  return PCArray;

}

void ModuleSanitizerCoverageAFL::CreateFunctionLocalArrays(
    Function &F, ArrayRef<BasicBlock *> AllBlocks, uint32_t special) {

  if (Options.TracePCGuard)
    FunctionGuardArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size() + special, F, Int32Ty, SanCovGuardsSectionName);

}

bool ModuleSanitizerCoverageAFL::InjectCoverage(
    Function &F, ArrayRef<BasicBlock *> AllBlocks, bool IsLeafFunc) {

  if (AllBlocks.empty()) return false;

  uint32_t        cnt_cov = 0, cnt_sel = 0, cnt_sel_inc = 0;
  static uint32_t first = 1;

  for (auto &BB : F) {

    for (auto &IN : BB) {

      CallInst *callInst = nullptr;

      if ((callInst = dyn_cast<CallInst>(&IN))) {

        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
        if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
        StringRef FuncName = Callee->getName();
        if (!FuncName.compare(StringRef("dlopen")) ||
            !FuncName.compare(StringRef("_dlopen"))) {

          fprintf(stderr,
                  "WARNING: dlopen() detected. To have coverage for a library "
                  "that your target dlopen()'s this must either happen before "
                  "__AFL_INIT() or you must use AFL_PRELOAD to preload all "
                  "dlopen()'ed libraries!\n");
          continue;

        }

        if (!FuncName.compare(StringRef("__afl_coverage_interesting"))) {

          cnt_cov++;

        }

      }

      SelectInst *selectInst = nullptr;

      if ((selectInst = dyn_cast<SelectInst>(&IN))) {

        Value *c = selectInst->getCondition();
        auto   t = c->getType();
        if (t->getTypeID() == llvm::Type::IntegerTyID) {

          cnt_sel++;
          cnt_sel_inc += 2;

        }

        else if (t->getTypeID() == llvm::Type::FixedVectorTyID) {

          FixedVectorType *tt = dyn_cast<FixedVectorType>(t);
          if (tt) {

            cnt_sel++;
            cnt_sel_inc += (tt->getElementCount().getKnownMinValue() * 2);

          }

        }

      }

    }

  }

  CreateFunctionLocalArrays(F, AllBlocks, first + cnt_cov + cnt_sel_inc);

  if (first) { first = 0; }
  selects += cnt_sel;

  uint32_t special = 0, local_selects = 0, skip_next = 0;

  for (auto &BB : F) {

    for (auto &IN : BB) {

      CallInst *callInst = nullptr;

      if ((callInst = dyn_cast<CallInst>(&IN))) {

        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
        if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
        StringRef FuncName = Callee->getName();
        if (FuncName.compare(StringRef("__afl_coverage_interesting"))) continue;

#if LLVM_VERSION_MAJOR >= 20
        // test canary
        InstrumentationIRBuilder IRB(callInst);
#else
        IRBuilder<> IRB(callInst);
#endif

        if (!FunctionGuardArray) {

          fprintf(stderr,
                  "SANCOV: FunctionGuardArray is NULL, failed to emit "
                  "instrumentation.");
          continue;

        }

        Value *GuardPtr = IRB.CreateIntToPtr(
            IRB.CreateAdd(
                IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                ConstantInt::get(IntptrTy, (++special + AllBlocks.size()) * 4)),
            Int32PtrTy);

        LoadInst *Idx = IRB.CreateLoad(IRB.getInt32Ty(), GuardPtr);
        ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(Idx);

        callInst->setOperand(1, Idx);

      }

      SelectInst *selectInst = nullptr;

      if (!skip_next && (selectInst = dyn_cast<SelectInst>(&IN))) {

        uint32_t    vector_cnt = 0;
        Value      *condition = selectInst->getCondition();
        Value      *result;
        auto        t = condition->getType();
        IRBuilder<> IRB(selectInst->getNextNode());

        if (t->getTypeID() == llvm::Type::IntegerTyID) {

          if (!FunctionGuardArray) {

            fprintf(stderr,
                    "SANCOV: FunctionGuardArray is NULL, failed to emit "
                    "instrumentation.");
            continue;

          }

          auto GuardPtr1 = IRB.CreateIntToPtr(
              IRB.CreateAdd(
                  IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                  ConstantInt::get(
                      IntptrTy,
                      (cnt_cov + local_selects++ + AllBlocks.size()) * 4)),
              Int32PtrTy);

          auto GuardPtr2 = IRB.CreateIntToPtr(
              IRB.CreateAdd(
                  IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                  ConstantInt::get(
                      IntptrTy,
                      (cnt_cov + local_selects++ + AllBlocks.size()) * 4)),
              Int32PtrTy);

          result = IRB.CreateSelect(condition, GuardPtr1, GuardPtr2);

        } else

#if LLVM_VERSION_MAJOR >= 14
            if (t->getTypeID() == llvm::Type::FixedVectorTyID) {

          FixedVectorType *tt = dyn_cast<FixedVectorType>(t);
          if (tt) {

            uint32_t elements = tt->getElementCount().getFixedValue();
            vector_cnt = elements;
            if (elements) {

              FixedVectorType *GuardPtr1 =
                  FixedVectorType::get(Int32PtrTy, elements);
              FixedVectorType *GuardPtr2 =
                  FixedVectorType::get(Int32PtrTy, elements);
              Value *x, *y;

              if (!FunctionGuardArray) {

                fprintf(stderr,
                        "SANCOV: FunctionGuardArray is NULL, failed to emit "
                        "instrumentation.");
                continue;

              }

              Value *val1 = IRB.CreateIntToPtr(
                  IRB.CreateAdd(
                      IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                      ConstantInt::get(
                          IntptrTy,
                          (cnt_cov + local_selects++ + AllBlocks.size()) * 4)),
                  Int32PtrTy);
              x = IRB.CreateInsertElement(GuardPtr1, val1, (uint64_t)0);

              Value *val2 = IRB.CreateIntToPtr(
                  IRB.CreateAdd(
                      IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                      ConstantInt::get(
                          IntptrTy,
                          (cnt_cov + local_selects++ + AllBlocks.size()) * 4)),
                  Int32PtrTy);
              y = IRB.CreateInsertElement(GuardPtr2, val2, (uint64_t)0);

              for (uint64_t i = 1; i < elements; i++) {

                val1 = IRB.CreateIntToPtr(
                    IRB.CreateAdd(
                        IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                        ConstantInt::get(IntptrTy, (cnt_cov + local_selects++ +
                                                    AllBlocks.size()) *
                                                       4)),
                    Int32PtrTy);
                x = IRB.CreateInsertElement(x, val1, i);

                val2 = IRB.CreateIntToPtr(
                    IRB.CreateAdd(
                        IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                        ConstantInt::get(IntptrTy, (cnt_cov + local_selects++ +
                                                    AllBlocks.size()) *
                                                       4)),
                    Int32PtrTy);
                y = IRB.CreateInsertElement(y, val2, i);

              }

              result = IRB.CreateSelect(condition, x, y);

            }

          }

        } else

#endif
        {

          // fprintf(stderr, "UNHANDLED: %u\n", t->getTypeID());
          unhandled++;
          continue;

        }

        uint32_t vector_cur = 0;

        /* Load SHM pointer */

        LoadInst *MapPtr =
            IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
        ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(MapPtr);

        while (1) {

          /* Get CurLoc */
          LoadInst *CurLoc = nullptr;
          Value    *MapPtrIdx = nullptr;

          /* Load counter for CurLoc */
          if (!vector_cnt) {

            CurLoc = IRB.CreateLoad(IRB.getInt32Ty(), result);
            ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(CurLoc);
            MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, CurLoc);

          } else {

            auto element = IRB.CreateExtractElement(result, vector_cur++);
            auto elementptr = IRB.CreateIntToPtr(element, Int32PtrTy);
            auto elementld = IRB.CreateLoad(IRB.getInt32Ty(), elementptr);
            ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(elementld);
            MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, elementld);

          }

          if (use_threadsafe_counters) {

            IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                                llvm::MaybeAlign(1),
#endif
                                llvm::AtomicOrdering::Monotonic);

          } else {

            LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
            ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(Counter);

            /* Update bitmap */

            Value *Incr = IRB.CreateAdd(Counter, One);

            if (skip_nozero == NULL) {

              auto cf = IRB.CreateICmpEQ(Incr, Zero);
              auto carry = IRB.CreateZExt(cf, Int8Ty);
              Incr = IRB.CreateAdd(Incr, carry);

            }

            StoreInst *StoreCtx = IRB.CreateStore(Incr, MapPtrIdx);
            ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(StoreCtx);

          }

          if (!vector_cnt) {

            vector_cnt = 2;
            break;

          } else if (vector_cnt == vector_cur) {

            break;

          }

        }

        skip_next = 1;
        instr += vector_cnt;

      } else {

        skip_next = 0;

      }

    }

  }

  if (AllBlocks.empty() && !special && !local_selects) return false;

  if (!AllBlocks.empty())
    for (size_t i = 0, N = AllBlocks.size(); i < N; i++)
      InjectCoverageAtBlock(F, *AllBlocks[i], i, IsLeafFunc);

  return true;

}

// For every switch statement we insert a call:
// __sanitizer_cov_trace_switch(CondValue,
//      {NumCases, ValueSizeInBits, Case0Value, Case1Value, Case2Value, ... })

void ModuleSanitizerCoverageAFL::InjectTraceForSwitch(
    Function &, ArrayRef<Instruction *> SwitchTraceTargets) {

  for (auto I : SwitchTraceTargets) {

    if (SwitchInst *SI = dyn_cast<SwitchInst>(I)) {

      IRBuilder<>                 IRB(I);
      SmallVector<Constant *, 16> Initializers;
      Value                      *Cond = SI->getCondition();
      if (Cond->getType()->getScalarSizeInBits() >
          Int64Ty->getScalarSizeInBits())
        continue;
      Initializers.push_back(ConstantInt::get(Int64Ty, SI->getNumCases()));
      Initializers.push_back(
          ConstantInt::get(Int64Ty, Cond->getType()->getScalarSizeInBits()));
      if (Cond->getType()->getScalarSizeInBits() <
          Int64Ty->getScalarSizeInBits())
        Cond = IRB.CreateIntCast(Cond, Int64Ty, false);
      for (auto It : SI->cases()) {

        Constant *C = It.getCaseValue();
        if (C->getType()->getScalarSizeInBits() <
            Int64Ty->getScalarSizeInBits())
          C = ConstantExpr::getCast(CastInst::ZExt, It.getCaseValue(), Int64Ty);
        Initializers.push_back(C);

      }

      llvm::sort(drop_begin(Initializers, 2),
                 [](const Constant *A, const Constant *B) {

                   return cast<ConstantInt>(A)->getLimitedValue() <
                          cast<ConstantInt>(B)->getLimitedValue();

                 });

      ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, Initializers.size());
      GlobalVariable *GV = new GlobalVariable(
          *CurModule, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
          ConstantArray::get(ArrayOfInt64Ty, Initializers),
          "__sancov_gen_cov_switch_values");
      IRB.CreateCall(SanCovTraceSwitchFunction,
                     {Cond, IRB.CreatePointerCast(GV, Int64PtrTy)});

    }

  }

}

void ModuleSanitizerCoverageAFL::InjectTraceForCmp(
    Function &, ArrayRef<Instruction *> CmpTraceTargets) {

  for (auto I : CmpTraceTargets) {

    if (ICmpInst *ICMP = dyn_cast<ICmpInst>(I)) {

      IRBuilder<> IRB(ICMP);
      Value      *A0 = ICMP->getOperand(0);
      Value      *A1 = ICMP->getOperand(1);
      if (!A0->getType()->isIntegerTy()) continue;
      uint64_t TypeSize = DL->getTypeStoreSizeInBits(A0->getType());
      int      CallbackIdx = TypeSize == 8    ? 0
                             : TypeSize == 16 ? 1
                             : TypeSize == 32 ? 2
                             : TypeSize == 64 ? 3
                                              : -1;
      if (CallbackIdx < 0) continue;
      // __sanitizer_cov_trace_cmp((type_size << 32) | predicate, A0, A1);
      auto CallbackFunc = SanCovTraceCmpFunction[CallbackIdx];
      bool FirstIsConst = isa<ConstantInt>(A0);
      bool SecondIsConst = isa<ConstantInt>(A1);
      // If both are const, then we don't need such a comparison.
      if (FirstIsConst && SecondIsConst) continue;
      // If only one is const, then make it the first callback argument.
      if (FirstIsConst || SecondIsConst) {

        CallbackFunc = SanCovTraceConstCmpFunction[CallbackIdx];
        if (SecondIsConst) std::swap(A0, A1);

      }

      auto Ty = Type::getIntNTy(*C, TypeSize);
      IRB.CreateCall(CallbackFunc, {IRB.CreateIntCast(A0, Ty, true),
                                    IRB.CreateIntCast(A1, Ty, true)});

    }

  }

}

void ModuleSanitizerCoverageAFL::InjectCoverageAtBlock(Function   &F,
                                                       BasicBlock &BB,
                                                       size_t      Idx,
                                                       bool        IsLeafFunc) {

  BasicBlock::iterator IP = BB.getFirstInsertionPt();
  bool                 IsEntryBB = &BB == &F.getEntryBlock();
  DebugLoc             EntryLoc;

  if (IsEntryBB) {

    if (auto SP = F.getSubprogram())
      EntryLoc = DILocation::get(SP->getContext(), SP->getScopeLine(), 0, SP);
    // Keep static allocas and llvm.localescape calls in the entry block.  Even
    // if we aren't splitting the block, it's nice for allocas to be before
    // calls.
    IP = PrepareToSplitEntryBlock(BB, IP);
#if LLVM_VERSION_MAJOR < 15

  } else {

    EntryLoc = IP->getDebugLoc();
    if (!EntryLoc)
      if (auto *SP = F.getSubprogram())
        EntryLoc = DILocation::get(SP->getContext(), 0, 0, SP);
#endif

  }

#if LLVM_VERSION_MAJOR >= 16
  InstrumentationIRBuilder IRB(&*IP);
#else
  IRBuilder<> IRB(&*IP);
#endif
  if (EntryLoc) IRB.SetCurrentDebugLocation(EntryLoc);
  if (Options.TracePCGuard) {

    /*
      auto GuardPtr = IRB.CreateIntToPtr(
          IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                        ConstantInt::get(IntptrTy, Idx * 4)),
          Int32PtrTy);
      IRB.CreateCall(SanCovTracePCGuard, GuardPtr)->setCannotMerge();
    */

    /* Get CurLoc */

    Value *GuardPtr = IRB.CreateIntToPtr(
        IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                      ConstantInt::get(IntptrTy, Idx * 4)),
        Int32PtrTy);

    LoadInst *CurLoc = IRB.CreateLoad(IRB.getInt32Ty(), GuardPtr);
    ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(CurLoc);

    /* Load SHM pointer */

    LoadInst *MapPtr = IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
    ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(MapPtr);

    /* Load counter for CurLoc */

    Value *MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, CurLoc);

    if (use_threadsafe_counters) {

      IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                          llvm::MaybeAlign(1),
#endif
                          llvm::AtomicOrdering::Monotonic);

    } else {

      LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
      ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(Counter);

      /* Update bitmap */

      Value *Incr = IRB.CreateAdd(Counter, One);

      if (skip_nozero == NULL) {

        auto cf = IRB.CreateICmpEQ(Incr, Zero);
        auto carry = IRB.CreateZExt(cf, Int8Ty);
        Incr = IRB.CreateAdd(Incr, carry);

      }

      StoreInst *StoreCtx = IRB.CreateStore(Incr, MapPtrIdx);
      ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(StoreCtx);

    }

    // done :)

    //    IRB.CreateCall(SanCovTracePCGuard, Offset)->setCannotMerge();
    //    IRB.CreateCall(SanCovTracePCGuard, GuardPtr)->setCannotMerge();
    ++instr;

  }

}

std::string ModuleSanitizerCoverageAFL::getSectionName(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatCOFF()) {

    if (Section == SanCovCountersSectionName) return ".SCOV$CM";
    if (Section == SanCovBoolFlagSectionName) return ".SCOV$BM";
    if (Section == SanCovPCsSectionName) return ".SCOVP$M";
    return ".SCOV$GM";  // For SanCovGuardsSectionName.

  }

  if (TargetTriple.isOSBinFormatMachO()) return "__DATA,__" + Section;
  return "__" + Section;

}

std::string ModuleSanitizerCoverageAFL::getSectionStart(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$start$__DATA$__" + Section;
  return "__start___" + Section;

}

std::string ModuleSanitizerCoverageAFL::getSectionEnd(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$end$__DATA$__" + Section;
  return "__stop___" + Section;

}

//----------------------------------------------------------
// HorseFuzz: hashset library
hashset_t hashset_create() {
  hashset_t set = (hashset_t) calloc(1, sizeof(struct hashset_st));

  if (set == NULL) {
    return NULL;
  }
  set->nbits = 3;
  set->capacity = (size_t)(1 << set->nbits);
  set->mask = set->capacity - 1;
  set->items = (unsigned long*) calloc(set->capacity, sizeof(size_t));
  if (set->items == NULL) {
    hashset_destroy(set);
    return NULL;
  }
  set->nitems = 0;
  set->n_deleted_items = 0;
  return set;
}

size_t hashset_num_items(hashset_t set) {
  return set->nitems;
}

void hashset_destroy(hashset_t set) {
  if (set) {
    free(set->items);
  }
  free(set);
}

static int hashset_add_member(hashset_t set, void *item) {
  size_t value = (size_t)item;
  size_t ii;

  if (value == 0 || value == 1) {
    return -1;
  }

  ii = set->mask & (prime_1 * value);

  while (set->items[ii] != 0 && set->items[ii] != 1) {
    if (set->items[ii] == value) {
      return 0;
    } else {
      /* search free slot */
      ii = set->mask & (ii + prime_2);
    }
  }
  set->nitems++;
  if (set->items[ii] == 1) {
    set->n_deleted_items--;
  }
  set->items[ii] = value;
  return 1;
}

static void maybe_rehash(hashset_t set) {
  size_t *old_items;
  size_t old_capacity, ii;

  if (set->nitems + set->n_deleted_items >= (double)set->capacity * 0.85) {
    old_items = set->items;
    old_capacity = set->capacity;
    set->nbits++;
    set->capacity = (size_t)(1 << set->nbits);
    set->mask = set->capacity - 1;
    set->items = (unsigned long*) calloc(set->capacity, sizeof(size_t));
    set->nitems = 0;
    set->n_deleted_items = 0;
    assert(set->items);
    for (ii = 0; ii < old_capacity; ii++) {
      hashset_add_member(set, (void *)old_items[ii]);
    }
    free(old_items);
  }
}

int hashset_add(hashset_t set, void *item) {
  int rv = hashset_add_member(set, item);
  maybe_rehash(set);
  return rv;
}

int hashset_remove(hashset_t set, void *item) {
  size_t value = (size_t)item;
  size_t ii = set->mask & (prime_1 * value);

  while (set->items[ii] != 0) {
    if (set->items[ii] == value) {
      set->items[ii] = 1;
      set->nitems--;
      set->n_deleted_items++;
      return 1;
    } else {
      ii = set->mask & (ii + prime_2);
    }
  }
  return 0;
}

int hashset_is_member(hashset_t set, void *item) {
  size_t value = (size_t)item;
  size_t ii = set->mask & (prime_1 * value);

  while (set->items[ii] != 0) {
    if (set->items[ii] == value) {
      return 1;
    } else {
      ii = set->mask & (ii + prime_2);
    }
  }
  return 0;
}

// Simple hash32 function implementation
uint32_t hash32(const void *key, size_t length, uint32_t seed) {
  const uint8_t *data = (const uint8_t*)key;
  uint32_t h1 = seed;
  size_t i;

  for (i = 0; i < length; i++) {
    h1 = (h1 ^ data[i]) * 0x01000193;
  }

  return h1;
}
//----------------------------------------------------------

