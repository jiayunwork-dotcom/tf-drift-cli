from __future__ import annotations

import os
import re
from typing import Any

from ..models.resource import HclAttribute, HclBlock, HclConfig, ResourceRef


class HclParseError(Exception):
    def __init__(self, message: str, line: int = 0, file_path: str = ""):
        self.line = line
        self.file_path = file_path
        super().__init__(f"{file_path}:{line}: {message}" if file_path else f"line {line}: {message}")


class HclLexer:
    TOKEN_PATTERNS = [
        ("COMMENT_LINE", r"//[^\n]*"),
        ("COMMENT_BLOCK", r"/\*[\s\S]*?\*/"),
        ("STRING", r'"(?:[^"\\]|\\.)*"'),
        ("HEREDOC", r"<<[-~]?(\w+)\n[\s\S]*?\n\s*\1"),
        ("NUMBER", r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?"),
        ("BOOL", r"\b(true|false)\b"),
        ("NULL", r"\bnull\b"),
        ("IDENTIFIER", r"[a-zA-Z_][a-zA-Z0-9_-]*"),
        ("LBRACE", r"\{"),
        ("RBRACE", r"\}"),
        ("LBRACKET", r"\["),
        ("RBRACKET", r"\]"),
        ("LPAREN", r"\("),
        ("RPAREN", r"\)"),
        ("EQUALS", r"="),
        ("COLON", r":"),
        ("COMMA", r","),
        ("DOT", r"\."),
        ("QUESTION", r"\?"),
        ("ARROW", r"=>"),
        ("ELLIPSIS", r"\.\.\."),
        ("NEWLINE", r"\n"),
        ("WS", r"[ \t\r]+"),
    ]

    def __init__(self, source: str):
        self.source = source
        self.tokens: list[tuple[str, str, int]] = []
        self._tokenize()

    def _tokenize(self):
        pos = 0
        line = 1
        combined = "|".join(
            f"(?P<{name}>{pattern})"
            for name, pattern in self.TOKEN_PATTERNS
        )
        regex = re.compile(combined)

        while pos < len(self.source):
            match = regex.match(self.source, pos)
            if not match:
                if self.source[pos] == "\n":
                    line += 1
                    pos += 1
                    continue
                pos += 1
                continue

            token_type = match.lastgroup
            token_value = match.group()
            start_line = line

            if token_type == "NEWLINE":
                line += 1
                pos = match.end()
                if self.tokens and self.tokens[-1][0] != "NEWLINE":
                    self.tokens.append(("NEWLINE", "\n", start_line))
                continue

            if token_type in ("WS", "COMMENT_LINE", "COMMENT_BLOCK"):
                line += token_value.count("\n")
                pos = match.end()
                continue

            if token_type == "HEREDOC":
                line += token_value.count("\n")

            self.tokens.append((token_type, token_value, start_line))
            line += token_value.count("\n")
            pos = match.end()


class HclParser:
    def __init__(self, source: str, file_path: str = ""):
        self.lexer = HclLexer(source)
        self.tokens = self.lexer.tokens
        self.pos = 0
        self.file_path = file_path
        self.current_line = 0

    def _peek(self, offset: int = 0) -> tuple[str, str, int] | None:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return None

    def _advance(self) -> tuple[str, str, int] | None:
        if self.pos < len(self.tokens):
            tok = self.tokens[self.pos]
            self.pos += 1
            self.current_line = tok[2]
            return tok
        return None

    def _expect(self, token_type: str) -> tuple[str, str, int]:
        tok = self._peek()
        if tok is None:
            raise HclParseError(f"Expected {token_type}, got EOF", self.current_line, self.file_path)
        if tok[0] != token_type:
            raise HclParseError(f"Expected {token_type}, got {tok[0]} ({tok[1]!r})", tok[2], self.file_path)
        return self._advance()

    def _match(self, token_type: str) -> tuple[str, str, int] | None:
        tok = self._peek()
        if tok and tok[0] == token_type:
            return self._advance()
        return None

    def _at_block_start(self) -> bool:
        tok = self._peek()
        return tok is not None and tok[0] == "IDENTIFIER" and tok[1] in (
            "resource", "data", "variable", "locals", "output", "module",
            "terraform", "provider",
        )

    def parse(self) -> HclConfig:
        config = HclConfig()
        while self.pos < len(self.tokens):
            if self._at_block_start():
                try:
                    block = self._parse_top_block()
                    if block:
                        self._register_block(block, config)
                except HclParseError:
                    self._skip_to_next_block()
            else:
                self._advance()
        return config

    def _register_block(self, block: HclBlock, config: HclConfig):
        bt = block.block_type
        if bt == "resource":
            key = block.address()
            config.resources[key] = block
        elif bt == "data":
            key = block.address()
            config.data_sources[key] = block
        elif bt == "variable":
            name = block.labels[0] if block.labels else ""
            config.variables[name] = block
        elif bt == "locals":
            for k, v in block.attributes.items():
                config.locals_[k] = v
        elif bt == "output":
            name = block.labels[0] if block.labels else ""
            config.outputs[name] = block
        elif bt == "module":
            name = block.labels[0] if block.labels else ""
            config.modules[name] = block

    def _skip_to_next_block(self):
        while self.pos < len(self.tokens):
            tok = self._peek()
            if tok and tok[0] == "IDENTIFIER" and tok[1] in (
                "resource", "data", "variable", "locals", "output", "module",
                "terraform", "provider",
            ):
                return
            self._advance()

    def _parse_top_block(self) -> HclBlock | None:
        tok = self._expect("IDENTIFIER")
        block_type = tok[1]
        line = tok[2]

        labels: list[str] = []
        while True:
            next_tok = self._peek()
            if next_tok and next_tok[0] == "STRING":
                label_tok = self._advance()
                labels.append(self._unquote(label_tok[1]))
            elif next_tok and next_tok[0] == "IDENTIFIER":
                label_tok = self._advance()
                labels.append(label_tok[1])
            else:
                break

        self._expect("LBRACE")

        attributes: dict[str, HclAttribute] = {}
        nested_blocks: list[HclBlock] = []
        for_each_expr = None
        count_expr = None
        provider = None
        depends_on: list[str] = []

        while True:
            next_tok = self._peek()
            if next_tok is None:
                break
            if next_tok[0] == "RBRACE":
                self._advance()
                break
            if next_tok[0] == "NEWLINE":
                self._advance()
                continue

            if next_tok[0] == "IDENTIFIER":
                ident = next_tok[1]

                if ident == "dynamic":
                    dyn_block = self._parse_dynamic_block()
                    if dyn_block:
                        nested_blocks.append(dyn_block)
                    continue

                if ident in ("for_each", "count", "provider", "depends_on", "lifecycle", "provisioner", "connection"):
                    self._advance()
                    if ident in ("lifecycle", "provisioner", "connection"):
                        while self._peek() and self._peek()[0] == "NEWLINE":
                            self._advance()
                        self._skip_brace_block()
                    else:
                        self._expect("EQUALS")
                        if ident == "for_each":
                            for_each_expr = self._read_expression()
                        elif ident == "count":
                            count_expr = self._read_expression()
                        elif ident == "provider":
                            provider = self._read_expression()
                        elif ident == "depends_on":
                            depends_on = self._parse_depends_on()
                        else:
                            self._read_expression()
                    self._match("COMMA")
                    self._match("NEWLINE")
                    continue

                is_nested_block = self._is_nested_block()
                if is_nested_block:
                    nested = self._parse_nested_block(ident)
                    nested.source_file = self.file_path
                    nested.source_line = next_tok[2]
                    nested_blocks.append(nested)
                else:
                    self._advance()
                    if self._match("EQUALS"):
                        attr = self._parse_attribute_value(ident)
                        if attr:
                            attributes[attr.key] = attr
                    self._match("NEWLINE")
            else:
                self._advance()

        return HclBlock(
            block_type=block_type,
            labels=labels,
            attributes=attributes,
            nested_blocks=nested_blocks,
            source_file=self.file_path,
            source_line=line,
            for_each_expr=for_each_expr,
            count_expr=count_expr,
            provider=provider,
            depends_on=depends_on,
        )

    def _is_nested_block(self) -> bool:
        save = self.pos
        self._advance()
        next_tok = self._peek()
        while next_tok and next_tok[0] == "NEWLINE":
            self._advance()
            next_tok = self._peek()
        self.pos = save
        return next_tok is not None and next_tok[0] == "LBRACE"

    def _parse_nested_block(self, name: str) -> HclBlock:
        self._advance()
        while self._peek() and self._peek()[0] == "NEWLINE":
            self._advance()
        self._expect("LBRACE")

        attributes: dict[str, HclAttribute] = {}
        nested_blocks: list[HclBlock] = []

        while True:
            next_tok = self._peek()
            if next_tok is None:
                break
            if next_tok[0] == "RBRACE":
                self._advance()
                break
            if next_tok[0] == "NEWLINE":
                self._advance()
                continue

            if next_tok[0] == "IDENTIFIER":
                ident = next_tok[1]
                if ident == "dynamic":
                    dyn = self._parse_dynamic_block()
                    if dyn:
                        nested_blocks.append(dyn)
                    continue
                is_nested = self._is_nested_block()
                if is_nested:
                    nested = self._parse_nested_block(ident)
                    nested_blocks.append(nested)
                else:
                    self._advance()
                    if self._match("EQUALS"):
                        attr = self._parse_attribute_value(ident)
                        if attr:
                            attributes[attr.key] = attr
                    self._match("COMMA")
                    self._match("NEWLINE")
            else:
                self._advance()

        return HclBlock(
            block_type=name,
            labels=[],
            attributes=attributes,
            nested_blocks=nested_blocks,
        )

    def _parse_dynamic_block(self) -> HclBlock | None:
        tok = self._peek()
        if not tok or tok[1] != "dynamic":
            return None

        self._advance()
        label_tok = self._peek()
        block_name = ""
        if label_tok and label_tok[0] == "IDENTIFIER":
            block_name = label_tok[1]
            self._advance()

        self._expect("LBRACE")

        attributes: dict[str, HclAttribute] = {}
        nested_blocks: list[HclBlock] = []

        while True:
            next_tok = self._peek()
            if next_tok is None:
                break
            if next_tok[0] == "RBRACE":
                self._advance()
                break
            if next_tok[0] == "NEWLINE":
                self._advance()
                continue

            if next_tok[0] == "IDENTIFIER":
                ident = next_tok[1]
                is_nested = self._is_nested_block()
                if is_nested:
                    nested = self._parse_nested_block(ident)
                    nested_blocks.append(nested)
                else:
                    self._advance()
                    if self._match("EQUALS"):
                        attr = self._parse_attribute_value(ident)
                        if attr:
                            attributes[attr.key] = attr
                    self._match("COMMA")
                    self._match("NEWLINE")
            else:
                self._advance()

        return HclBlock(
            block_type="dynamic",
            labels=[block_name],
            attributes=attributes,
            nested_blocks=nested_blocks,
            is_dynamic=True,
        )

    def _parse_attribute(self, key: str) -> HclAttribute | None:
        self._expect("EQUALS")
        return self._parse_attribute_value(key)

    def _parse_attribute_value(self, key: str) -> HclAttribute | None:
        tok = self._peek()
        if tok is None:
            return None

        if tok[0] == "LBRACE":
            value = self._parse_object_or_map()
            return HclAttribute(key=key, value=value, is_expression=False)
        elif tok[0] == "LBRACKET":
            value = self._parse_list()
            return HclAttribute(key=key, value=value, is_expression=False)
        elif tok[0] == "STRING":
            self._advance()
            raw = tok[1]
            unquoted = self._unquote(raw)
            refs = self._extract_refs_from_string(unquoted)
            is_expr = bool(refs) or "${" in raw
            expr_text = unquoted if is_expr else None
            is_conditional = "?" in unquoted and ":" in unquoted
            return HclAttribute(
                key=key,
                value=unquoted,
                is_expression=is_expr,
                expression_text=expr_text,
                references=refs,
                is_conditional=is_conditional,
            )
        elif tok[0] == "NUMBER":
            self._advance()
            val: Any = tok[1]
            if "." in val:
                val = float(val)
            else:
                val = int(val)
            return HclAttribute(key=key, value=val)
        elif tok[0] == "BOOL":
            self._advance()
            return HclAttribute(key=key, value=tok[1] == "true")
        elif tok[0] == "NULL":
            self._advance()
            return HclAttribute(key=key, value=None)
        elif tok[0] == "IDENTIFIER":
            self._advance()
            ident_val = tok[1]
            refs = self._extract_refs_from_string(ident_val)
            is_conditional = False
            cond_tok = self._peek()
            if cond_tok and cond_tok[0] == "QUESTION":
                is_conditional = True
                expr_parts = [ident_val]
                while self.pos < len(self.tokens):
                    t = self._peek()
                    if t and t[0] not in ("COMMA", "RBRACE", "RBRACKET", "NEWLINE"):
                        expr_parts.append(self._advance()[1])
                    else:
                        break
                return HclAttribute(
                    key=key,
                    value=" ".join(expr_parts),
                    is_expression=True,
                    expression_text=" ".join(expr_parts),
                    references=refs,
                    is_conditional=True,
                )
            return HclAttribute(
                key=key,
                value=ident_val,
                is_expression=True,
                expression_text=ident_val,
                references=refs,
            )
        else:
            self._advance()
            return None

    def _parse_object_or_map(self) -> dict[str, Any]:
        self._expect("LBRACE")
        result: dict[str, Any] = {}

        while True:
            tok = self._peek()
            if tok is None:
                break
            if tok[0] == "RBRACE":
                self._advance()
                break
            if tok[0] == "NEWLINE":
                self._advance()
                continue

            if tok[0] in ("IDENTIFIER", "STRING"):
                key = tok[1]
                if tok[0] == "STRING":
                    key = self._unquote(key)
                self._advance()
                if self._match("EQUALS") or self._match("COLON"):
                    val_attr = self._parse_attribute_value(key)
                    if val_attr:
                        result[key] = val_attr.value if not val_attr.is_expression else val_attr.expression_text or val_attr.value
                self._match("COMMA")
                self._match("NEWLINE")
            elif tok[0] == "LBRACE":
                nested = self._parse_object_or_map()
                result[f"_nested_{len(result)}"] = nested
            else:
                self._advance()

        return result

    def _parse_list(self) -> list[Any]:
        self._expect("LBRACKET")
        result: list[Any] = []

        while True:
            tok = self._peek()
            if tok is None:
                break
            if tok[0] == "RBRACKET":
                self._advance()
                break
            if tok[0] == "NEWLINE":
                self._advance()
                continue

            if tok[0] == "STRING":
                self._advance()
                result.append(self._unquote(tok[1]))
            elif tok[0] == "NUMBER":
                self._advance()
                val: Any = tok[1]
                if "." in val:
                    val = float(val)
                else:
                    val = int(val)
                result.append(val)
            elif tok[0] == "BOOL":
                self._advance()
                result.append(tok[1] == "true")
            elif tok[0] == "LBRACE":
                result.append(self._parse_object_or_map())
            elif tok[0] == "LBRACKET":
                result.append(self._parse_list())
            elif tok[0] == "IDENTIFIER":
                expr = self._read_expression()
                result.append(expr)
            elif tok[0] == "FOR" or (tok[0] == "IDENTIFIER" and tok[1] == "for"):
                expr = self._read_expression()
                result.append(expr)
            else:
                self._advance()
                continue

            self._match("COMMA")
            self._match("NEWLINE")

        return result

    def _read_expression(self) -> str:
        parts: list[str] = []
        depth_brace = 0
        depth_bracket = 0
        depth_paren = 0

        while self.pos < len(self.tokens):
            tok = self._peek()
            if tok is None:
                break

            if depth_brace == 0 and depth_bracket == 0 and depth_paren == 0:
                if tok[0] in ("COMMA", "NEWLINE"):
                    break
                if tok[0] == "RBRACE":
                    break
                if tok[0] == "RBRACKET" and depth_bracket == 0:
                    break

            if tok[0] == "LBRACE":
                depth_brace += 1
            elif tok[0] == "RBRACE":
                depth_brace -= 1
                if depth_brace < 0:
                    break
            elif tok[0] == "LBRACKET":
                depth_bracket += 1
            elif tok[0] == "RBRACKET":
                depth_bracket -= 1
                if depth_bracket < 0:
                    break
            elif tok[0] == "LPAREN":
                depth_paren += 1
            elif tok[0] == "RPAREN":
                depth_paren -= 1
                if depth_paren < 0:
                    break

            parts.append(tok[1])
            self._advance()

        expr = " ".join(parts)
        return expr

    def _parse_depends_on(self) -> list[str]:
        self._expect("LBRACKET")
        deps: list[str] = []

        while True:
            tok = self._peek()
            if tok is None:
                break
            if tok[0] == "NEWLINE":
                self._advance()
                continue
            if tok[0] == "RBRACKET":
                self._advance()
                break

            dep = self._read_expression()
            dep = dep.strip().strip('"').replace('"', '')
            if dep:
                deps.append(dep)
            self._match("COMMA")
            self._match("NEWLINE")

        return deps

    def _skip_brace_block(self):
        depth = 0
        while self.pos < len(self.tokens):
            tok = self._advance()
            if tok is None:
                break
            if tok[0] == "LBRACE":
                depth += 1
            elif tok[0] == "RBRACE":
                depth -= 1
                if depth <= 0:
                    break

    def _unquote(self, s: str) -> str:
        if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
            inner = s[1:-1]
            inner = inner.replace('\\"', '"')
            inner = inner.replace("\\n", "\n")
            inner = inner.replace("\\t", "\t")
            inner = inner.replace("\\\\", "\\")
            return inner
        return s

    def _extract_refs_from_string(self, s: str) -> list[ResourceRef]:
        refs: list[ResourceRef] = []
        seen: set[str] = set()

        patterns = [
            r'\$\{(.*?)\}',
            r'\b(var\.[a-zA-Z_][a-zA-Z0-9_.]*)\b',
            r'\b(local\.[a-zA-Z_][a-zA-Z0-9_.]*)\b',
            r'\b(data\.[a-zA-Z_][a-zA-Z0-9_.]*)\b',
            r'\b(module\.[a-zA-Z_][a-zA-Z0-9_.]*)\b',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, s):
                ref_str = match.group(1) if pattern.startswith(r'\$\{') else match.group(0)
                ref_str = ref_str.strip()
                if ref_str and ref_str not in seen:
                    seen.add(ref_str)
                    parts = ref_str.split(".")
                    ref_type = "resource"
                    module_path = None
                    resource_type = None
                    resource_name = None
                    attribute = None

                    idx = 0
                    if parts[0] == "module" and len(parts) >= 2:
                        module_path = parts[1]
                        idx = 2

                    remaining = parts[idx:]
                    if remaining and remaining[0] == "var":
                        ref_type = "var"
                        resource_name = remaining[1] if len(remaining) > 1 else None
                    elif remaining and remaining[0] == "local":
                        ref_type = "local"
                        resource_name = remaining[1] if len(remaining) > 1 else None
                    elif remaining and remaining[0] == "data":
                        ref_type = "data"
                        resource_type = "data"
                        if len(remaining) >= 3:
                            resource_name = remaining[2]
                            attribute = ".".join(remaining[3:]) if len(remaining) > 3 else None
                    elif len(remaining) >= 2:
                        resource_type = remaining[0]
                        resource_name = remaining[1]
                        attribute = ".".join(remaining[2:]) if len(remaining) > 2 else None

                    refs.append(ResourceRef(
                        ref_type=ref_type,
                        module_path=module_path,
                        resource_type=resource_type,
                        resource_name=resource_name,
                        attribute=attribute,
                        raw=ref_str,
                    ))

        return refs


def parse_tf_file(file_path: str) -> HclConfig:
    with open(file_path, "r", encoding="utf-8") as f:
        source = f.read()
    parser = HclParser(source, file_path)
    return parser.parse()


def parse_config_dir(config_dir: str) -> HclConfig:
    merged = HclConfig()

    if not os.path.isdir(config_dir):
        if os.path.isfile(config_dir) and config_dir.endswith(".tf"):
            result = parse_tf_file(config_dir)
            _merge_configs(merged, result)
            merged.source_files.append(config_dir)
        return merged

    for root, dirs, files in os.walk(config_dir):
        dirs[:] = [d for d in dirs if d not in (".terraform", ".git", "node_modules")]
        for fname in files:
            if fname.endswith(".tf"):
                fpath = os.path.join(root, fname)
                try:
                    result = parse_tf_file(fpath)
                    _merge_configs(merged, result)
                    merged.source_files.append(fpath)
                except (HclParseError, UnicodeDecodeError):
                    pass

    return merged


def _merge_configs(target: HclConfig, source: HclConfig):
    for key, block in source.resources.items():
        target.resources[key] = block
    for key, block in source.data_sources.items():
        target.data_sources[key] = block
    for key, block in source.variables.items():
        target.variables[key] = block
    for key, attr in source.locals_.items():
        target.locals_[key] = attr
    for key, block in source.outputs.items():
        target.outputs[key] = block
    for key, block in source.modules.items():
        target.modules[key] = block
