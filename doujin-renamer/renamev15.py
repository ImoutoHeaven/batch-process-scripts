import os
import sys
import re
import shutil
from datetime import datetime
from typing import Dict, List

############################
# 分类关键词 & 配置
############################

category_keywords = {
    'source': [
        'Pixiv', 'Patreon', 'Fanbox', 'fanbox', 'pixiv', 'patreon', 'DL版', '赞助', 'skeb'
    ],
    'translator_group': [
        '汉化','翻译','漢化','翻譯','渣翻','机翻','个人','個人','死兆修会',
        '機翻','中文','繁体','想舔羽月的jio组','賣水槍的小男孩','同人组',
        '烤肉man','漫画の茜','忍殺團','今泉紅太狼','悠月工房','个汉','個漢','翻訳','是小狐狸哦','zc2333','黑暗月光石','邊境牧羊犬','官中','禁漫天堂','恶魔波刚','查拉先生', '宇宙田协'
    ],
    'translation_version': [
        '重嵌', '無修正', '无修正', '换源', '換源', '去码', '水印', '渣嵌','重置','瞎嵌'
    ],
    'version': [
        'v2','v3','v4','v5','v6','v7','v8','v9','v10','v11','v12'
    ],
    'timestamp': None
}

# 用来做 ( ... ) => [ ... ] 的关键字
part_keys_for_parentheses = ('source', 'translator_group', 'translation_version')

# 分类顺序，注意在里面新增了一个 'misc' 用来容纳不匹配任何关键词的 []
category_order = [
    'misc',                # 不匹配任何已知关键字的归到 misc
    'translator_group',    # [汉化组名]
    'translation_version', # [无修正]等版本类别
    'source',              # [DL版]等来源标记
    'version',             # [v2]等版本号
    'timestamp'            # 时间戳放最后
]

############################
# 一系列辅助函数 (带可选 debug)
############################

def clean_empty_brackets(s: str, debug=False) -> str:
    """移除空的()和[]，并去除多余空格。"""
    prev = None
    result = s
    pattern_empty_square = re.compile(r'\[\s*\]')
    pattern_empty_paren = re.compile(r'\(\s*\)')
    while prev != result:
        prev = result
        before_sub = result
        result = pattern_empty_square.sub('', result)
        result = pattern_empty_paren.sub('', result)
        result = re.sub(r'\s+', ' ', result).strip()
        if debug and before_sub != result:
            print(f"[DEBUG] clean_empty_brackets: '{before_sub}' => '{result}'")
    return result

def light_bracket_fix(s: str, debug=False) -> str:
    """如果检测到多余/缺失方括号或圆括号，做一次轻量的修正。"""
    before = s
    cnt_open_sq = s.count('[')
    cnt_close_sq = s.count(']')
    cnt_open_par = s.count('(')
    cnt_close_par = s.count(')')

    if cnt_open_sq == cnt_close_sq + 1:
        s2 = re.sub(r'\[\[', '[', s, count=1)
        if s2 != s and debug:
            print(f"[DEBUG] light_bracket_fix: fix '[[' => '['")
        s = s2
    elif cnt_close_sq == cnt_open_sq + 1:
        s2 = re.sub(r'\]\]', ']', s, count=1)
        if s2 != s and debug:
            print(f"[DEBUG] light_bracket_fix: fix ']]' => ']'")
        s = s2

    if cnt_open_par == cnt_close_par + 1:
        s2 = re.sub(r'\(\(', '(', s, count=1)
        if s2 != s and debug:
            print(f"[DEBUG] light_bracket_fix: fix '((' => '('")
        s = s2
    elif cnt_close_par == cnt_open_par + 1:
        s2 = re.sub(r'\)\)', ')', s, count=1)
        if s2 != s and debug:
            print(f"[DEBUG] light_bracket_fix: fix '))' => ')'")
        s = s2

    if debug and s != before:
        print(f"[DEBUG] light_bracket_fix: '{before}' => '{s}'")
    return s

def check_brackets(s: str, debug=False):
    """检查括号是否匹配，不匹配则抛出 ValueError。"""
    bracket_pairs = {'[': ']', '(': ')'}
    for opening, closing in bracket_pairs.items():
        depth = 0
        for i, c in enumerate(s):
            if c == opening:
                depth += 1
            elif c == closing:
                depth -= 1
                if depth < 0:
                    if debug:
                        print(f"[DEBUG] check_brackets: Unmatched closing '{closing}' found at index {i}.")
                    raise ValueError(f"Unmatched closing '{closing}' in '{s}'. Please handle manually.")
        if depth != 0:
            if debug:
                print(f"[DEBUG] check_brackets: Unmatched opening '{opening}' found, depth != 0.")
            raise ValueError(f"Unmatched opening '{opening}' in '{s}'. Please handle manually.")
    return True

def gather_bracket_keywords(cat_dict, keys, debug=False):
    """汇总部分分类关键词，如 translator_group、source 等。"""
    all_kw = []
    for k in keys:
        vals = cat_dict.get(k)
        if vals:
            all_kw.extend(vals)
    # 去重且保留顺序
    unique_list = list(dict.fromkeys(all_kw))
    if debug:
        print(f"[DEBUG] gather_bracket_keywords => {unique_list}")
    return unique_list

def replace_paren_with_bracket_on_keywords(name: str, keywords_list, debug=False) -> str:
    """
    若 (xxx) 内含有指定关键词之一，则把它改成 [xxx]。
    """
    pattern_keywords = '|'.join(map(re.escape, keywords_list))
    if debug:
        print(f"[DEBUG] replace_paren_with_bracket_on_keywords => pattern_keywords: {pattern_keywords}")
    pattern_paren = re.compile(r'\([^)]*(?:' + pattern_keywords + r')[^)]*\)', re.IGNORECASE)

    def _replace(m):
        content = m.group(0)
        if debug:
            print(f"[DEBUG]   matched paren content: {content}")
        inner = content[1:-1]
        return "[" + inner + "]"

    before_sub = name
    new_name = pattern_paren.sub(_replace, name)
    if debug and new_name != before_sub:
        print(f"[DEBUG] replace_paren_with_bracket_on_keywords: '{before_sub}' => '{new_name}'")
    return new_name

def create_category_pattern(category, words, debug=False):
    """根据category与对应keywords生成一个用于匹配方括号内容的正则表达式。"""
    if category == 'translator_group':
        keywords = '|'.join(map(re.escape, words))
        return re.compile(r'\[[^\]]*(?:' + keywords + r')[^\]]*\]', re.IGNORECASE)
    elif category in ('source', 'translation_version'):
        keywords = '|'.join(map(re.escape, words))
        return re.compile(r'\[[^\]]*(?:' + keywords + r')[^\]]*\]', re.IGNORECASE)
    elif category in ('version', 'timestamp'):
        keywords = '|'.join(map(re.escape, words))
        return re.compile(r'^(' + '|'.join(map(re.escape, words)) + r')$', re.IGNORECASE)
    else:
        return None

def standardize_timestamp(timestamp_str, debug=False):
    """把 YYMMDD => YYYYMMDD, 或 YYYYMMDDxx => YYYYMMDD."""
    if not timestamp_str:
        return None
    
    digits = ''.join(filter(str.isdigit, timestamp_str))
    before = timestamp_str
    after = None
    if len(digits) == 6:  # YYMMDD -> YYYYMMDD
        after = f"20{digits}"
    elif len(digits) == 8:  # YYYYMMDD
        after = digits
    elif len(digits) == 10:  # YYYYMMDDvv
        after = digits[:8]

    if debug and after and after != before:
        print(f"[DEBUG] standardize_timestamp: '{before}' => '{after}'")
    return after

def process_version_tag(name, debug=False):
    """把 v2 之类的标记补成 [v2]"""
    before = name
    pattern_bracketed = re.compile(r'\[+v(\d+(?:\.\d+)?)\]+', re.IGNORECASE)
    name = pattern_bracketed.sub(lambda m: f'[v{m.group(1)}]', name)
    
    pattern = re.compile(r'(?<![A-Za-z0-9\[\]])v(\d+(?:\.\d+)?)(?![A-Za-z0-9\[\]])', re.IGNORECASE)
    name = pattern.sub(lambda m: f'[v{m.group(1)}]', name)
    
    if debug and name != before:
        print(f"[DEBUG] process_version_tag: '{before}' => '{name}'")
    return name

def rearrange_tags(name, debug=False):
    """
    把文件名里所有 [分类] 取出来，根据 translator_group -> translation_version -> source -> misc -> version -> timestamp 顺序进行重组。
    (这是最初的“初步分类”函数；不匹配的标签暂时不放 'misc'，只保留recognized的分类。)
    """
    if debug:
        print(f"[DEBUG] rearrange_tags: input => '{name}'")

    # 准备分类正则
    category_patterns = {}
    for category, words in category_keywords.items():
        if words:
            category_patterns[category] = create_category_pattern(category, words, debug=debug)
        else:
            if category == 'timestamp':
                category_patterns['timestamp'] = re.compile(r'^(\d{6}|\d{8}|\d{10})$')

    bracket_tag_pattern = re.compile(r'\[([^\[\]]+)\]')
    matched_tag_positions = []
    category_tags = {cat: [] for cat in category_order}

    # 搜索所有 [xxx] 
    for match in re.finditer(bracket_tag_pattern, name):
        tag_content = match.group(1).strip()
        tag_start = match.start()
        tag_end = match.end()
        categorized = False

        # 如果是时间戳
        if category_patterns['timestamp'].match(tag_content):
            std_timestamp = standardize_timestamp(tag_content, debug=debug)
            if std_timestamp:
                category_tags['timestamp'].append(std_timestamp)
                categorized = True
                matched_tag_positions.append((tag_start, tag_end))
                continue

        # 检查其他分类
        for category in category_order:
            if category in ('timestamp', 'misc'):
                continue
            ptn = category_patterns.get(category)
            if ptn and ptn.match(f'[{tag_content}]'):
                category_tags[category].append(tag_content)
                categorized = True
                matched_tag_positions.append((tag_start, tag_end))
                if debug:
                    print(f"[DEBUG] rearrange_tags: matched '{tag_content}' => category '{category}'")
                break
        # 不在这里处理 "misc"，留给后续 reorder_suffix 或其他逻辑

    # 从后往前删除匹配的标签
    name_list = list(name)
    for start, end in sorted(matched_tag_positions, key=lambda x: -x[0]):
        del name_list[start:end]
    name_without_tags = ''.join(name_list).strip()

    # 按顺序重组
    rearranged_tags = []
    for category in category_order:
        tags = category_tags[category]
        if tags:
            # 同类内字母顺序
            tags.sort(key=str.lower)
            rearranged_tags.extend(f'[{tag}]' for tag in tags)

    final_name = name_without_tags
    if rearranged_tags:
        final_name = final_name + ' ' + ' '.join(rearranged_tags)

    final_name = re.sub(r'\s+', ' ', final_name).strip()
    final_name = clean_empty_brackets(final_name, debug=debug)
    
    if debug:
        print(f"[DEBUG] rearrange_tags: output => '{final_name}'")
    return final_name



def convert_naked_timestamp_to_bracket(name: str, debug=False) -> str:
    """
    将文件名中裸奔的 6/8/10/11 位数字（疑似时间戳）加上方括号。
    例如:
      "Fur just wanna be friend 20250113 [水猫汉化]" 
      => "Fur just wanna be friend [20250113] [水猫汉化]"
    """
    # \b(...)\b 确保是“单词边界”，避免把 longer123456short 这种中途片段误当作时间戳
    pattern = re.compile(r'\b(\d{6}|\d{8}|\d{10}|\d{11})\b')

    def _replace(m):
        digits = m.group(1)
        return f'[{digits}]'

    new_name = pattern.sub(_replace, name)
    if debug and new_name != name:
        print(f"[DEBUG] convert_naked_timestamp_to_bracket: '{name}' => '{new_name}'")
    return new_name

############################
# 分类辅助: detect_category_for_bracket
############################

def detect_category_for_bracket(tag_content, debug=False):
    """
    根据已有的 category_keywords 来判断属于哪个分类，
    只要包含任意一个关键词，即可视为对应分类，
    如果都不匹配则归入 'misc'。
    """

    # 先检查是否是时间戳
    if re.match(r'^(?:\d{6}|\d{8}|\d{10})$', tag_content):
        if debug:
            print(f"[DEBUG] detect_category_for_bracket: '{tag_content}' => 'timestamp'")
        return 'timestamp'
    
    # 再检查其他分类
    for cat, keywords in category_keywords.items():
        # 跳过 'timestamp'
        if cat == 'timestamp':
            continue
        
        # 如果这个分类定义了关键词，遍历检查
        if keywords:
            # “只要包含关键词，就认定为此分类”
            for kw in keywords:
                if kw.lower() in tag_content.lower():
                    if debug:
                        print(f"[DEBUG] detect_category_for_bracket: '{tag_content}' => '{cat}' (matched '{kw}')")
                    return cat

    # 若所有分类都不匹配则归入 'misc'
    if debug:
        print(f"[DEBUG] detect_category_for_bracket: '{tag_content}' => 'misc'")
    return 'misc'

############################
# 改进后的 reorder_suffix 函数
############################

def reorder_suffix(name_without_ext, debug=False):
    """
    对已经确认 is_filename_compliant==True 的文件名(不带扩展名)进行后缀 ()、[] 的重排。
    
    改进点：
      1. 前缀若是 (xxx)[xxx(xxx)] / [xxx(xxx)] 等，整体识别为 prefix，不拆分 (xxx)。
      2. 后缀仅从最末尾连续收集 ( )、[ ]，中途遇到正文字符即停止。
      3. 剩余部分即为正文 middle。
      4. 最后把 () 内文本字母顺序、[] 内文本按分类再同类排序后，依次接在末尾。
    """
    if debug:
        print(f"[DEBUG] reorder_suffix: input => '{name_without_ext}'")

    raw = name_without_ext
    length = len(raw)
    pos = 0

    # -------------------------
    # 1) 解析“前缀” prefix
    # -------------------------
    prefix = ""
    prefix_end = 0

    if raw.startswith("("):
        # 类型1或3： (xxx)[xxx] or (xxx)[xxx(xxx)]
        depth = 0
        found_first_paren = False
        while pos < length:
            if raw[pos] == '(':
                depth += 1
            elif raw[pos] == ')':
                depth -= 1
                if depth == 0:
                    pos += 1  # 到 ) 后
                    found_first_paren = True
                    break
            pos += 1

        if not found_first_paren:
            # 理论上不应发生
            if debug:
                print("[DEBUG] reorder_suffix: no matching ')' found for prefix (xxx)")
            return raw

        # 把 (xxx) 部分放进 prefix
        prefix = raw[:pos]

        # 跳过空格
        while pos < length and raw[pos].isspace():
            pos += 1

        # 下一个必须是 '['
        if pos < length and raw[pos] == '[':
            depth = 0
            found_bracket = False
            bracket_start = pos
            while pos < length:
                if raw[pos] == '[':
                    depth += 1
                elif raw[pos] == ']':
                    depth -= 1
                    if depth == 0:
                        pos += 1
                        found_bracket = True
                        break
                pos += 1
            if found_bracket:
                # (xxx)[xxx(xxx)] 全部当 prefix
                prefix = raw[:pos]
            else:
                if debug:
                    print("[DEBUG] reorder_suffix: prefix bracket not closed properly")
                return raw
        else:
            # 如果( 开头却没接 [ ，那就到此为止
            if debug:
                print("[DEBUG] reorder_suffix: expected '[' after '(...)' but not found.")
            # prefix 已经到 pos 位置
        prefix_end = pos

    elif raw.startswith("["):
        # 类型2或4： [xxx] or [xxx(xxx)]
        depth = 0
        found_bracket = False
        while pos < length:
            if raw[pos] == '[':
                depth += 1
            elif raw[pos] == ']':
                depth -= 1
                if depth == 0:
                    pos += 1
                    found_bracket = True
                    break
            pos += 1
        if found_bracket:
            prefix = raw[:pos]
        else:
            if debug:
                print("[DEBUG] reorder_suffix: bracket prefix not closed properly.")
            return raw
        prefix_end = pos

    # 跳过空格
    while prefix_end < length and raw[prefix_end].isspace():
        prefix_end += 1

    if debug:
        print(f"[DEBUG] reorder_suffix: Detected prefix => '{prefix}'")
        print(f"[DEBUG] reorder_suffix: prefix_end => {prefix_end}")

    # -------------------------
    # 2) 从右往左收集“后缀” token
    # -------------------------
    suffix_tokens = []
    i = length - 1
    while i >= prefix_end:
        if raw[i].isspace():
            i -= 1
            continue

        if raw[i] in [')', ']']:
            # 找匹配 ( / [
            if raw[i] == ')':
                depth = 0
                end_paren = i
                while i >= prefix_end:
                    if raw[i] == ')':
                        depth += 1
                    elif raw[i] == '(':
                        depth -= 1
                        if depth == 0:
                            token_start = i
                            token = raw[token_start : end_paren+1]
                            suffix_tokens.append(token)
                            break
                    i -= 1
                else:
                    break
                i -= 1
            else: # raw[i] == ']'
                depth = 0
                end_brack = i
                while i >= prefix_end:
                    if raw[i] == ']':
                        depth += 1
                    elif raw[i] == '[':
                        depth -= 1
                        if depth == 0:
                            token_start = i
                            token = raw[token_start : end_brack+1]
                            suffix_tokens.append(token)
                            break
                    i -= 1
                else:
                    break
                i -= 1
        else:
            # 遇到别的字符 => 后缀解析到此为止
            break

    # 后缀 tokens 是从右往左收集，reverse 成正常顺序
    suffix_tokens.reverse()

    if debug:
        print(f"[DEBUG] reorder_suffix: collected suffix tokens => {suffix_tokens}")

    # suffix_start
    if suffix_tokens:
        first_suffix_token = suffix_tokens[0]
        start_idx = raw.find(first_suffix_token, prefix_end)
        suffix_start = start_idx
    else:
        suffix_start = length

    middle_part = raw[prefix_end : suffix_start]

    if debug:
        print(f"[DEBUG] reorder_suffix: middle_part => '{middle_part}'")

    # -------------------------
    # 3) 解析 suffix_tokens => () 组 + [] 组
    # -------------------------
    paren_list = []
    bracket_list = []
    for t in suffix_tokens:
        if t.startswith('(') and t.endswith(')'):
            paren_list.append(t[1:-1].strip())
        elif t.startswith('[') and t.endswith(']'):
            bracket_list.append(t[1:-1].strip())

    if debug:
        print(f"[DEBUG] reorder_suffix: paren_list => {paren_list}")
        print(f"[DEBUG] reorder_suffix: bracket_list => {bracket_list}")

    # (a) ()组按字母顺序
    old_plist = paren_list[:]
    paren_list.sort(key=str.lower)
    if debug and old_plist != paren_list:
        print(f"[DEBUG] reorder_suffix: sorted paren_list => {paren_list}")

    # (b) []组按分类 => translator_group->translation_version->source->misc->version->timestamp
    categorized_tags: Dict[str, List[str]] = {cat: [] for cat in category_order}
    for bc in bracket_list:
        cat = detect_category_for_bracket(bc, debug=debug)
        categorized_tags[cat].append(bc)

    # 同一类内按字母顺序
    for cat in category_order:
        old_list = categorized_tags[cat][:]
        categorized_tags[cat].sort(key=str.lower)
        if debug and old_list != categorized_tags[cat]:
            print(f"[DEBUG] reorder_suffix: sorted bracket_list for '{cat}' => {categorized_tags[cat]}")

    bracket_sorted = []
    for cat in category_order:
        for tg in categorized_tags[cat]:
            bracket_sorted.append(f'[{tg}]')

    if debug:
        print(f"[DEBUG] reorder_suffix: bracket_sorted => {bracket_sorted}")

    # -------------------------
    # 4) 重组
    # -------------------------
    new_suffix = ''
    if paren_list:
        new_suffix += ' ' + ' '.join(f'({p})' for p in paren_list)
    if bracket_sorted:
        new_suffix += ' ' + ' '.join(bracket_sorted)

    new_name = prefix + middle_part + new_suffix

    # 去掉多余空格
    new_name = re.sub(r'\s+', ' ', new_name).strip()
    # 移除空括号
    new_name = re.sub(r'\(\s*\)', '', new_name)
    new_name = re.sub(r'\[\s*\]', '', new_name)
    new_name = re.sub(r'\s+', ' ', new_name).strip()

    new_name = new_name.replace('[', ' [').replace(']', '] ').replace('(', ' (').replace(')', ') ')
    new_name = re.sub(r'\s+', ' ', new_name).strip()
    new_name = re.sub(r'\) \]', ')]', new_name)
    new_name = re.sub(r'\[ ', '[', new_name)
    new_name = re.sub(r' \]', ']', new_name)
    new_name = clean_empty_brackets(new_name, debug=debug) 

    if debug:
        print(f"[DEBUG] reorder_suffix: final => '{new_name}'")

    return new_name

############################
# 主 process_name/process_filename
############################

def process_name(name, debug=False):
    """对去掉拓展名的文件名进行一系列处理，返回处理后的名字。"""
    if debug:
        print(f"[DEBUG] process_name: Original => '{name}'")

    # 1) 移除空括号
    name = clean_empty_brackets(name, debug=debug)
    
    # 2) 替换【等奇形括号为正常[]
    before_sub = name
    name = re.sub(r'[【［]', '[', name)
    name = re.sub(r'[】］]', ']', name)
    name = name.replace('（', '(').replace('）', ')')
    if debug and name != before_sub:
        print(f"[DEBUG] unify brackets: '{before_sub}' => '{name}'")

    # 3) 轻量修正
    name = light_bracket_fix(name, debug=debug)
    name = clean_empty_brackets(name, debug=debug)

    # 4) check_brackets
    try:
        check_brackets(name, debug=debug)
    except ValueError:
        if debug:
            print(f"[DEBUG] check_brackets raised ValueError, trying light_bracket_fix again")
        name = light_bracket_fix(name, debug=debug)
        name = clean_empty_brackets(name, debug=debug)
        check_brackets(name, debug=debug)

    # 5) 移除 (同人誌)
    before_sub = name
    name = name.replace('(同人誌)', '')
    name = clean_empty_brackets(name, debug=debug)
    if debug and name != before_sub:
        print(f"[DEBUG] remove '(同人誌)': '{before_sub}' => '{name}'")

    # 6) 替换含关键词的(...) => [...]
    bracket_keywords = gather_bracket_keywords(category_keywords, part_keys_for_parentheses, debug=debug)
    name = replace_paren_with_bracket_on_keywords(name, bracket_keywords, debug=debug)
    name = clean_empty_brackets(name, debug=debug)

    # 7) [v2] 标记处理
    name = process_version_tag(name, debug=debug)
    name = clean_empty_brackets(name, debug=debug)

    # 8) 如果最开头是某些组别关键字 [xxx]，挪到后面
    move_keywords_pattern = '|'.join(map(re.escape, bracket_keywords))
    match = re.match(r'^(\[[^\[\]]*(?:' + move_keywords_pattern + r')[^\[\]]*\])\s*(.*)', name, flags=re.IGNORECASE)
    if match:
        bracket_to_move = match.group(1)
        rest_of_name = match.group(2)
        old_name = name
        name = rest_of_name.strip() + ' ' + bracket_to_move
        name = clean_empty_brackets(name, debug=debug)
        if debug and old_name != name:
            print(f"[DEBUG] move bracket from start to end: '{old_name}' => '{name}'")

    # 9) 替换下划线 => 空格，加空格以分隔括号
    before_sub = name
    name = name.replace('_', ' ')
    name = name.replace('[', ' [').replace(']', '] ').replace('(', ' (').replace(')', ') ')
    name = re.sub(r'\s+', ' ', name).strip()
    name = re.sub(r'\) \]', ')]', name)
    name = re.sub(r'\[ ', '[', name)
    name = re.sub(r' \]', ']', name)
    name = clean_empty_brackets(name, debug=debug)
    if debug and name != before_sub:
        print(f"[DEBUG] spacing brackets: '{before_sub}' => '{name}'")

    # 10) rearrange_tags (初步分类)
    old_name = name
    
    name = convert_naked_timestamp_to_bracket(name, debug=debug)
    
    name = rearrange_tags(name, debug=debug)
    if debug and name != old_name:
        print(f"[DEBUG] rearrange_tags => '{old_name}' => '{name}'")

    if debug:
        print(f"[DEBUG] process_name: Final => '{name}'")
    return name

def process_filename(filename, debug=False):
    """
    对单个文件名进行处理，包含对扩展名的拆分和拼装。
    """
    if filename.startswith('.'):
        # 隐藏文件(如 .gitignore)不处理
        if debug:
            print(f"[DEBUG] process_filename: skip hidden => '{filename}'")
        return filename

    parts = filename.rsplit('.', 1)
    if len(parts) == 2:
        name, ext = parts
    else:
        name, ext = filename, ''

    new_name_no_ext = process_name(name, debug=debug)
    ext = ext.strip()

    if ext:
        new_name = new_name_no_ext + '.' + ext
    else:
        new_name = new_name_no_ext

    if debug:
        print(f"[DEBUG] process_filename: final => '{new_name}'")
    return new_name

############################################
# is_filename_compliant
############################################

def is_filename_compliant(name, debug=False):
    """
    根据新需求：
    1) 文件开头可选 ( )，内容不得是系统关键字或时间戳（并且只能出现一次）。
    2) 接着必须出现 [ ]，内容不得是系统关键字或时间戳（只能出现一次）。
    3) 后面如果紧跟 ()、[]、{}，则不合规。
    4) 保留对 [vX] 与 [YYYYMMDD] 出现顺序的检查。
    """
    name_stripped = name.strip()
    if debug:
        print(f"[DEBUG] is_filename_compliant: checking => '{name_stripped}'")

    if not name_stripped:
        if debug:
            print("[DEBUG] => not compliant (empty)")
        return False

    if '[' not in name_stripped:
        if debug:
            print("[DEBUG] => not compliant (no '[' found)")
        return False

    system_keywords = set()
    for k, vals in category_keywords.items():
        if vals:
            for v in vals:
                system_keywords.add(v.lower())

    def is_timestamp_like(s):
        return re.match(r'^(?:\d{6}|\d{8}|\d{10})$', s)

    pos = 0
    length = len(name_stripped)

    # (1) 可选的开头 ( ) 解析
    if name_stripped.startswith('('):
        start = pos
        depth = 0
        found_paren = False
        while pos < length:
            c = name_stripped[pos]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    paren_content = name_stripped[start+1:pos].strip()
                    pos += 1
                    found_paren = True
                    if not paren_content:
                        if debug:
                            print("[DEBUG] => not compliant (empty parentheses)")
                        return False
                    if paren_content.lower() in system_keywords:
                        if debug:
                            print("[DEBUG] => not compliant (paren_content is system keyword)")
                        return False
                    if is_timestamp_like(paren_content):
                        if debug:
                            print("[DEBUG] => not compliant (paren_content is timestamp)")
                        return False
                    break
            pos += 1
        if depth != 0:
            if debug:
                print("[DEBUG] => not compliant (unmatched '(')")
            return False

    while pos < length and name_stripped[pos].isspace():
        pos += 1

    # (2) 接下来必须出现 [ ]
    if pos >= length or name_stripped[pos] != '[':
        if debug:
            print("[DEBUG] => not compliant ([ not found after optional paren)")
        return False

    bracket_start = pos
    pos += 1
    depth = 1
    while pos < length and depth > 0:
        if name_stripped[pos] == '[':
            depth += 1
        elif name_stripped[pos] == ']':
            depth -= 1
        pos += 1

    if depth != 0:
        if debug:
            print("[DEBUG] => not compliant (unmatched '[')")
        return False

    bracket_end = pos
    bracket_content = name_stripped[bracket_start+1:bracket_end-1].strip()
    if not bracket_content:
        if debug:
            print("[DEBUG] => not compliant (empty bracket)")
        return False

    if bracket_content.lower() in system_keywords:
        if debug:
            print("[DEBUG] => not compliant (bracket_content is system keyword)")
        return False
    if is_timestamp_like(bracket_content):
        if debug:
            print("[DEBUG] => not compliant (bracket_content is timestamp)")
        return False

    # (3) 后面若紧跟 ()、[]、{} => 不合规
    while pos < length and name_stripped[pos].isspace():
        pos += 1
    if pos < length and name_stripped[pos] in ['(', '[', '{']:
        if debug:
            print("[DEBUG] => not compliant (immediately '(' or '[' or '{' after bracket)")
        return False

    # (4) 保留 [vX] 和 [YYYYMMDD] 出现顺序检查
    tags = re.findall(r'\[([^\]]+)\]', name_stripped)
    if not tags:
        if debug:
            print("[DEBUG] => not compliant (no [tags] found at all)")
        return False

    version_tag = None
    timestamp_tag = None
    for tag in tags:
        if re.search(r'^v\d+(?:\.\d+)?$', tag, re.IGNORECASE):
            version_tag = tag
        elif re.match(r'^(?:\d{6}|\d{8}|\d{10})$', tag):
            timestamp_tag = tag

    if version_tag and timestamp_tag:
        version_pos = name_stripped.rindex(f'[{version_tag}]')
        timestamp_pos = name_stripped.rindex(f'[{timestamp_tag}]')
        if version_pos > timestamp_pos:
            if debug:
                print("[DEBUG] => not compliant ([vX] is after [timestamp])")
            return False

    if debug:
        print("[DEBUG] => compliant!")
    return True

############################
# OS 相关处理
############################

def parse_starting_tokens(name, debug=False):
    """
    解析从头开始若有 '[]' 或 '()' 的token。
    """
    tokens = []
    pos = 0
    length = len(name)
    while pos < length:
        while pos < length and name[pos] == ' ':
            pos += 1
        if pos >= length:
            break
        if name[pos] == '[':
            start = pos
            pos += 1
            depth = 1
            while pos < length and depth > 0:
                if name[pos] == '[':
                    depth += 1
                elif name[pos] == ']':
                    depth -= 1
                pos += 1
            if depth == 0:
                token = name[start:pos]
                tokens.append(('[]', token))
            else:
                break
        elif name[pos] == '(':
            start = pos
            pos += 1
            depth = 1
            while pos < length and depth > 0:
                if name[pos] == '(':
                    depth += 1
                elif name[pos] == ')':
                    depth -= 1
                pos += 1
            if depth == 0:
                token = name[start:pos]
                tokens.append(('()', token))
            else:
                break
        else:
            break
    if debug:
        print(f"[DEBUG] parse_starting_tokens => {tokens}")
    return tokens

def compare_files(file1, file2, debug=False):
    """比较两个文件的修改时间和大小，返回保留哪个。"""
    stat1 = os.stat(file1)
    stat2 = os.stat(file2)

    if debug:
        print(f"[DEBUG] compare_files => file1='{file1}', file2='{file2}'")
        print(f"         st_mtime => {stat1.st_mtime} vs {stat2.st_mtime}")
        print(f"         st_size  => {stat1.st_size} vs {stat2.st_size}")

    if stat1.st_mtime != stat2.st_mtime:
        return file1 if stat1.st_mtime < stat2.st_mtime else file2

    if stat1.st_size != stat2.st_size:
        return file1 if stat1.st_size < stat2.st_size else file2

    return file1

def ensure_temp_dir(folder_path, debug=False):
    """在folder_path下创建/确认temp目录存在。"""
    temp_dir = os.path.join(folder_path, 'temp')
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
        if debug:
            print(f"[DEBUG] ensure_temp_dir => created '{temp_dir}'")
    return temp_dir

def main(folder_path, dry_run=False, debug=False):
    """
    改进后的主函数:
      1) 先做预检, 如果发现括号不匹配, 打印问题文件名(去除后缀)让用户修正后退出
      2) 若无括号问题, 开始正式改名, 并只在改名前后做一次rename, 
         同时打印修改日志与不合规警告。
    """

    # ------------------ 阶段1: 括号匹配预检 ------------------
    unmatched_bracket_files = []
    try:
        items = os.listdir(folder_path)
    except FileNotFoundError:
        print(f"Error: Path '{folder_path}' does not exist.")
        return

    # 跳过名为 temp 的目录
    if 'temp' in items:
        items.remove('temp')

    # 对每个文件/目录，先只做 check_brackets 的预检
    for item in items:
        # 跳过隐藏文件或隐藏目录
        if item.startswith('.'):
            continue

        item_path = os.path.join(folder_path, item)

        # 如果是文件，需要去掉扩展名后再做 bracket 检查
        if os.path.isfile(item_path):
            base_no_ext, _ = os.path.splitext(item)
            try:
                # 若有括号不匹配, process_name 会抛 ValueError
                _ = process_name(base_no_ext, debug=debug)
            except ValueError:
                unmatched_bracket_files.append(base_no_ext)
        elif os.path.isdir(item_path):
            try:
                _ = process_name(item, debug=debug)
            except ValueError:
                unmatched_bracket_files.append(item)

    if unmatched_bracket_files:
        print("检测到以下名称存在括号不匹配，请修正后再运行脚本：")
        for fname in unmatched_bracket_files:
            print(fname)
        return  # 直接退出，不做后续改名

    # ------------------ 阶段2: 正式改名处理 ------------------
    warnings = []
    temp_dir = None
    rename_logs = []  # 用于记录所有实际(或将要)改名情况 (oldNameNoExt, newNameNoExt)

    # 重新获取目录下的项目(因为上面只做了预检, 没改动)
    items = os.listdir(folder_path)
    if 'temp' in items:
        items.remove('temp')

    for item in items:
        if item.startswith('.'):
            # 跳过隐藏
            continue

        item_path = os.path.join(folder_path, item)

        # =============== 文件处理 ===============
        if os.path.isfile(item_path):
            old_name_no_ext, old_ext = os.path.splitext(item)
            # 记录“原始名字(无后缀)”用于打印日志
            original_basename = old_name_no_ext

            # 第一步: 用 process_filename 获取规范化后的名称(含后缀)
            #         这里暂不改名, 仅得到“初步处理结果”
            processed_fullname = process_filename(item, debug=debug)
            processed_base_no_ext, processed_ext = os.path.splitext(processed_fullname)

            # 第二步: 检查合规 => reorder_suffix => 得到最终名字
            if is_filename_compliant(processed_base_no_ext, debug=debug):
                reordered_base_no_ext = reorder_suffix(processed_base_no_ext, debug=debug)
            else:
                # 不合规则不做 reorder_suffix
                reordered_base_no_ext = processed_base_no_ext
                warnings.append((processed_base_no_ext, "Does not conform to naming convention"))

            final_fullname = reordered_base_no_ext + processed_ext

            # 第三步: 若 final_fullname != item (说明确实要改名), 就只执行一次改名
            if final_fullname != item:
                final_path = os.path.join(folder_path, final_fullname)
                if not dry_run:
                    try:
                        os.rename(item_path, final_path)
                    except OSError as e:
                        # 处理重名冲突
                        if hasattr(e, 'winerror') and e.winerror == 183:
                            if temp_dir is None:
                                temp_dir = ensure_temp_dir(folder_path, debug=debug)
                            file_to_move = compare_files(item_path, final_path, debug=debug)
                            temp_path = os.path.join(temp_dir, os.path.basename(file_to_move))
                            counter = 1
                            base, ext = os.path.splitext(temp_path)
                            while os.path.exists(temp_path):
                                temp_path = f"{base}_{counter}{ext}"
                                counter += 1
                            shutil.move(file_to_move, temp_path)
                            # 若原文件被移走, 则无需再处理
                            if file_to_move == item_path:
                                continue
                        else:
                            # 其它错误 => 进 warnings
                            warnings.append((processed_base_no_ext, str(e)))
                    else:
                        # 如果成功改名, 记录日志
                        rename_logs.append((original_basename, reordered_base_no_ext))
                else:
                    # dry-run 模式只记录日志, 不实际改名
                    rename_logs.append((original_basename, reordered_base_no_ext))

        # =============== 目录处理 ===============
        elif os.path.isdir(item_path):
            old_dir_name = item
            original_basename = old_dir_name  # 目录没有扩展名

            # 第一步: 用 process_name 做初步规范化(目录无后缀)
            processed_dir_name = process_name(old_dir_name, debug=debug)

            # 第二步: 合规检查
            if is_filename_compliant(processed_dir_name, debug=debug):
                reordered_dir_name = reorder_suffix(processed_dir_name, debug=debug)
            else:
                reordered_dir_name = processed_dir_name
                warnings.append((processed_dir_name, "Does not conform to naming convention"))

            final_dir_name = reordered_dir_name

            # 第三步: 若有变化, 执行一次改名
            if final_dir_name != old_dir_name:
                final_path = os.path.join(folder_path, final_dir_name)
                if not dry_run:
                    try:
                        os.rename(item_path, final_path)
                    except OSError as e:
                        # 处理重名冲突
                        if hasattr(e, 'winerror') and e.winerror == 183:
                            if temp_dir is None:
                                temp_dir = ensure_temp_dir(folder_path, debug=debug)
                            file_to_move = compare_files(item_path, final_path, debug=debug)
                            temp_path = os.path.join(temp_dir, os.path.basename(file_to_move))
                            counter = 1
                            base, ext = os.path.splitext(temp_path)
                            while os.path.exists(temp_path):
                                temp_path = f"{base}_{counter}{ext}"
                                counter += 1
                            shutil.move(file_to_move, temp_path)
                            # 若原目录被移走, 则无需再处理
                            if file_to_move == item_path:
                                continue
                        else:
                            warnings.append((processed_dir_name, str(e)))
                    else:
                        rename_logs.append((original_basename, reordered_dir_name))
                else:
                    rename_logs.append((original_basename, reordered_dir_name))

    # ------------------ 打印改名日志 ------------------
    # 只打印确实发生(或将会发生)变化的条目: old => new
    # 其中 old/new 都是去掉后缀的部分(对目录名无所谓, 直接就是名称)
    if rename_logs:
        for i, (old_no_ext, new_no_ext) in enumerate(rename_logs, start=1):
            if old_no_ext != new_no_ext:
                print(f"--- file {i}/{len(rename_logs)} ---")
                print(f"{old_no_ext} ==>")
                print(f"{new_no_ext}")

    # ------------------ 打印警告 ------------------
    if warnings:
        print("\nWARNING: The following items had issues:")
        shown_set = set()
        for (w_name, w_err) in warnings:
            if w_name not in shown_set:
                print(w_name)
                shown_set.add(w_name)



############################
# 命令行入口
############################

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python script.py /path/to/folder [--dry-run] [--debug]")
        sys.exit(1)
        
    folder_path = sys.argv[1]
    dry_run = '--dry-run' in sys.argv
    debug_mode = '--debug' in sys.argv

    if not os.path.exists(folder_path):
        print(f"Error: Path '{folder_path}' does not exist.")
        sys.exit(1)

    if dry_run:
        print("Running in dry-run mode - no actual changes will be made")
    if debug_mode:
        print("Running in debug mode - verbose logs enabled")

    main(folder_path, dry_run=dry_run, debug=debug_mode)
