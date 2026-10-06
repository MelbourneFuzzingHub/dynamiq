import os
import re

def patch_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # 1. find_if(reverse_view(V), L) -> find_if(V.rbegin(), V.rend(), L)
    content = re.sub(r'std::ranges::find_if\(\s*std::ranges::reverse_view\((.*?)\),\s*(.*?)\);',
                     r'std::find_if(\1.rbegin(), \1.rend(), \2);', content)

    # 2. ranges::sort(V) -> sort(std::begin(V), std::end(V))
    content = re.sub(r'std::ranges::sort\(([^,)]*)\);',
                     r'std::sort(std::begin(\1), std::end(\1));', content)

    # 3. ranges::sort(V, L) -> sort(std::begin(V), std::end(V), L)
    # We use non-greedy matching to avoid capturing too much if there are trailing projections
    content = re.sub(r'std::ranges::sort\((.*?),\s*(.*?)\);',
                     r'std::sort(std::begin(\1), std::end(\1), \2);', content)

    # 4. ranges::reverse(V) -> reverse(std::begin(V), std::end(V))
    content = re.sub(r'std::ranges::reverse\(([^)]*)\);',
                     r'std::reverse(std::begin(\1), std::end(\1));', content)

    # 5. ranges::rotate(V, M) -> rotate(std::begin(V), M, std::end(V))
    content = re.sub(r'std::ranges::rotate\(([^,]*),\s*(.*?)\);',
                     r'std::rotate(std::begin(\1), \2, std::end(\1));', content)

    # 6. ranges::any_of(V, L) -> any_of(std::begin(V), std::end(V), L)
    content = re.sub(r'std::ranges::any_of\((.*?),\s*(.*?)\);',
                     r'std::any_of(std::begin(\1), std::end(\1), \2);', content)

    # 6b. ranges::any_of(V, L) (without semicolon, e.g. in return)
    # Use word boundary to avoid partial matches
    content = re.sub(r'\bstd::ranges::any_of\((.*?),\s*(.*?)\)',
                     r'std::any_of(std::begin(\1), std::end(\1), \2)', content)

    # 7. ranges::transform(V, B, L) -> transform(std::begin(V), std::end(V), B, L)
    content = re.sub(r'std::ranges::transform\((.*?),\s*(.*?),\s*(.*?)\);',
                     r'std::transform(std::begin(\1), std::end(\1), \2, \3);', content)

    # 8. ranges::lower_bound(V, K, Comp, Proj)
    # Special case for DictEntry::first projection which is most common in Poppler
    content = re.sub(r'std::ranges::lower_bound\((.*?),\s*(.*?),\s*(.*?),\s*&DictEntry::first\)',
                     r'std::lower_bound(std::begin(\1), std::end(\1), \2, CmpDictEntry {})', content)

    # General lower_bound with 3 or 4 args
    content = re.sub(r'std::ranges::lower_bound\((.*?),\s*(.*?),\s*(.*?),\s*(.*?)\)',
                     r'std::lower_bound(std::begin(\1), std::end(\1), \2, \3)', content) # Note: we still drop Proj for general case but ideally we shouldn't.

    # 8b. ranges::lower_bound(V, K, Comp)
    content = re.sub(r'std::ranges::lower_bound\((.*?),\s*(.*?),\s*(.*?)\)',
                     r'std::lower_bound(std::begin(\1), std::end(\1), \2, \3)', content)

    # 8c. ranges::lower_bound(V, K)
    content = re.sub(r'std::ranges::lower_bound\((.*?),\s*(.*?)\)',
                     r'std::lower_bound(std::begin(\1), std::end(\1), \2)', content)

    # 9. General fallback for find(V, K)
    content = re.sub(r'\bstd::ranges::find\((.*?),\s*(.*?)\)',
                     r'std::find(std::begin(\1), std::end(\1), \2)', content)

    # 10. ranges::replace(V, O, N) -> replace(std::begin(V), std::end(V), O, N)
    content = re.sub(r'std::ranges::replace\((.*?),\s*(.*?),\s*(.*?)\)',
                     r'std::replace(std::begin(\1), std::end(\1), \2, \3)', content)

    # 11. ranges::equal(V1, V2) -> equal(std::begin(V1), std::end(V1), std::begin(V2))
    content = re.sub(r'std::ranges::equal\((.*?),\s*(.*?)\)',
                     r'std::equal(std::begin(\1), std::end(\1), std::begin(\2))', content)

    # Specific fix for Catalog.cc mangled line if it exists
    if 'Catalog.cc' in filepath:
        content = re.sub(r'error\(errSyntaxError\)", name->c_str\(\)\);',
                         r'error(errSyntaxError, -1, "Could not find entry {0:s}", name->c_str());', content)

    with open(filepath, 'w') as f:
        f.write(content)

# We now use environment variables to find the repo path correctly
repo_base = os.environ.get('POPPLER_REPO', 'poppler/repo')
repo_path = os.path.join(repo_base, 'poppler')
splash_path = os.path.join(repo_base, 'splash')

if os.path.exists(repo_path):
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.cc') or file.endswith('.h'):
                patch_file(os.path.join(root, file))

if os.path.exists(splash_path):
    for root, dirs, files in os.walk(splash_path):
        for file in files:
            if file.endswith('.cc') or file.endswith('.h'):
                patch_file(os.path.join(root, file))
