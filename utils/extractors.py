from utils import helpers

#process func_ids.log file produced by horsefuzz-clang-fast
def extract_fname_src_dict(func_ids):
  fname_src_dict = dict()

  with open(func_ids, "r") as f:
    for line in f:
      # Skip empty or malformed lines
      if not line.strip():
        continue

      # Split by colon and validate structure
      tmpStrs = line.strip().split(":")
      if len(tmpStrs) != 2:
        print(f"Skipping malformed line: {line.strip()}")
        continue

      srcName = tmpStrs[0]

      # Further split the second part by space
      func_parts = tmpStrs[1].split()
      if len(func_parts) < 2:
        print(f"Skipping line with missing hashId: {line.strip()}")
        continue

      funcName = func_parts[0]
      hashId = func_parts[1]

      # Add to dictionary
      if funcName in fname_src_dict:
        if not helpers.tuple_exist(fname_src_dict, funcName, srcName, hashId):
            fname_src_dict[funcName].append((srcName, hashId))
      else:
        fname_src_dict[funcName] = [(srcName, hashId)]

  return fname_src_dict


#process func_bbs.log file produced by horsefuzz-clang-fast
def extract_fname_bbs_dict(func_bbs):
  fname_bbs_dict = dict()

  f = open(func_bbs, "r")
  for line in f:
    #sample line: png.c:png_get_header_version: 1
    tmpStrs = line.strip().split(":")
    if len(tmpStrs) != 3:
      continue
    srcName = tmpStrs[0].strip()
    funcName = tmpStrs[1].strip()
    bbCount = int(tmpStrs[2].strip())
   
    #ignore functions with no instrumented basic blocks 
    if bbCount > 0:
      if funcName in fname_bbs_dict.keys():
        if helpers.tuple_exist(fname_bbs_dict, funcName, srcName, bbCount) == False:
          fname_bbs_dict[funcName].append((srcName, bbCount))
      else:
        fname_bbs_dict[funcName] = [(srcName, bbCount)]

  f.close()
  return fname_bbs_dict
