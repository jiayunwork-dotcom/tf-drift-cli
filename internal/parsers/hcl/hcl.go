package hcl

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/tf-drift/tf-drift/internal/models"
)

type HclParseError struct {
	Message  string
	Line     int
	FilePath string
}

func (e *HclParseError) Error() string {
	if e.FilePath != "" {
		return fmt.Sprintf("%s:%d: %s", e.FilePath, e.Line, e.Message)
	}
	return fmt.Sprintf("line %d: %s", e.Line, e.Message)
}

type Token struct {
	Type    string
	Value   string
	Line    int
	Literal bool
}

const (
	TokIdentifier = "IDENTIFIER"
	TokString     = "STRING"
	TokNumber     = "NUMBER"
	TokBool       = "BOOL"
	TokNull       = "NULL"
	TokLBrace     = "LBRACE"
	TokRBrace     = "RBRACE"
	TokLBracket   = "LBRACKET"
	TokRBracket   = "RBRACKET"
	TokLParen     = "LPAREN"
	TokRParen     = "RPAREN"
	TokEquals     = "EQUALS"
	TokColon      = "COLON"
	TokComma      = "COMMA"
	TokDot        = "DOT"
	TokQuestion   = "QUESTION"
	TokArrow      = "ARROW"
	TokNewline    = "NEWLINE"
	TokEOF        = "EOF"
)

var topBlockKeywords = map[string]bool{
	"resource":   true,
	"data":       true,
	"variable":   true,
	"locals":     true,
	"output":     true,
	"module":     true,
	"terraform":  true,
	"provider":   true,
}

var skipBlocks = map[string]bool{
	"lifecycle":     true,
	"provisioner":   true,
	"connection":    true,
}

type Lexer struct {
	source string
	pos    int
	line   int
	tokens []Token
}

func NewLexer(source string) *Lexer {
	return &Lexer{
		source: source,
		line:   1,
	}
}

func (l *Lexer) Tokenize() []Token {
	for l.pos < len(l.source) {
		l.skipWhitespace()
		if l.pos >= len(l.source) {
			break
		}

		ch := l.source[l.pos]

		switch {
		case ch == '\n':
			l.tokens = append(l.tokens, Token{Type: TokNewline, Value: "\n", Line: l.line})
			l.line++
			l.pos++
		case ch == '/' && l.pos+1 < len(l.source) && (l.source[l.pos+1] == '/' || l.source[l.pos+1] == '*'):
			l.skipComment()
		case ch == '"':
			l.readString()
		case ch == '-' || (ch >= '0' && ch <= '9'):
			l.readNumber()
		case ch == '{':
			l.tokens = append(l.tokens, Token{Type: TokLBrace, Value: "{", Line: l.line})
			l.pos++
		case ch == '}':
			l.tokens = append(l.tokens, Token{Type: TokRBrace, Value: "}", Line: l.line})
			l.pos++
		case ch == '[':
			l.tokens = append(l.tokens, Token{Type: TokLBracket, Value: "[", Line: l.line})
			l.pos++
		case ch == ']':
			l.tokens = append(l.tokens, Token{Type: TokRBracket, Value: "]", Line: l.line})
			l.pos++
		case ch == '(':
			l.tokens = append(l.tokens, Token{Type: TokLParen, Value: "(", Line: l.line})
			l.pos++
		case ch == ')':
			l.tokens = append(l.tokens, Token{Type: TokRParen, Value: ")", Line: l.line})
			l.pos++
		case ch == '=':
			if l.pos+1 < len(l.source) && l.source[l.pos+1] == '>' {
				l.tokens = append(l.tokens, Token{Type: TokArrow, Value: "=>", Line: l.line})
				l.pos += 2
			} else {
				l.tokens = append(l.tokens, Token{Type: TokEquals, Value: "=", Line: l.line})
				l.pos++
			}
		case ch == ':':
			l.tokens = append(l.tokens, Token{Type: TokColon, Value: ":", Line: l.line})
			l.pos++
		case ch == ',':
			l.tokens = append(l.tokens, Token{Type: TokComma, Value: ",", Line: l.line})
			l.pos++
		case ch == '.':
			l.tokens = append(l.tokens, Token{Type: TokDot, Value: ".", Line: l.line})
			l.pos++
		case ch == '?':
			l.tokens = append(l.tokens, Token{Type: TokQuestion, Value: "?", Line: l.line})
			l.pos++
		case isIdentifierStart(ch):
			l.readIdentifier()
		default:
			l.pos++
		}
	}

	l.tokens = append(l.tokens, Token{Type: TokEOF, Value: "", Line: l.line})
	return l.tokens
}

func (l *Lexer) skipWhitespace() {
	for l.pos < len(l.source) {
		ch := l.source[l.pos]
		if ch == ' ' || ch == '\t' || ch == '\r' {
			l.pos++
		} else {
			break
		}
	}
}

func (l *Lexer) skipComment() {
	if l.pos+1 < len(l.source) && l.source[l.pos+1] == '/' {
		l.pos += 2
		for l.pos < len(l.source) && l.source[l.pos] != '\n' {
			l.pos++
		}
	} else if l.pos+1 < len(l.source) && l.source[l.pos+1] == '*' {
		l.pos += 2
		for l.pos+1 < len(l.source) && !(l.source[l.pos] == '*' && l.source[l.pos+1] == '/') {
			if l.source[l.pos] == '\n' {
				l.line++
			}
			l.pos++
		}
		l.pos += 2
	}
}

func (l *Lexer) readString() {
	startLine := l.line
	start := l.pos
	l.pos++
	heredoc := false
	if l.pos+2 < len(l.source) && l.source[l.pos] == '<' && l.source[l.pos+1] == '<' {
		heredoc = true
		for l.pos < len(l.source) && l.source[l.pos] != '\n' {
			l.pos++
		}
		if l.pos < len(l.source) {
			l.line++
			l.pos++
		}
	}

	for l.pos < len(l.source) {
		ch := l.source[l.pos]
		if ch == '\\' && l.pos+1 < len(l.source) {
			l.pos += 2
			continue
		}
		if ch == '\n' {
			l.line++
			if !heredoc {
				break
			}
		}
		if ch == '"' && !heredoc {
			l.pos++
			break
		}
		if heredoc && l.isHeredocEnd() {
			break
		}
		l.pos++
	}

	value := l.source[start:l.pos]
	l.tokens = append(l.tokens, Token{Type: TokString, Value: value, Line: startLine, Literal: true})
}

func (l *Lexer) isHeredocEnd() bool {
	return false
}

func (l *Lexer) readNumber() {
	startLine := l.line
	start := l.pos

	if l.source[l.pos] == '-' {
		l.pos++
	}

	for l.pos < len(l.source) && l.source[l.pos] >= '0' && l.source[l.pos] <= '9' {
		l.pos++
	}

	if l.pos < len(l.source) && l.source[l.pos] == '.' {
		l.pos++
		for l.pos < len(l.source) && l.source[l.pos] >= '0' && l.source[l.pos] <= '9' {
			l.pos++
		}
	}

	if l.pos < len(l.source) && (l.source[l.pos] == 'e' || l.source[l.pos] == 'E') {
		l.pos++
		if l.pos < len(l.source) && (l.source[l.pos] == '+' || l.source[l.pos] == '-') {
			l.pos++
		}
		for l.pos < len(l.source) && l.source[l.pos] >= '0' && l.source[l.pos] <= '9' {
			l.pos++
		}
	}

	value := l.source[start:l.pos]
	l.tokens = append(l.tokens, Token{Type: TokNumber, Value: value, Line: startLine})
}

func (l *Lexer) readIdentifier() {
	startLine := l.line
	start := l.pos

	for l.pos < len(l.source) && isIdentifierChar(l.source[l.pos]) {
		l.pos++
	}

	value := l.source[start:l.pos]

	if value == "true" || value == "false" {
		l.tokens = append(l.tokens, Token{Type: TokBool, Value: value, Line: startLine})
	} else if value == "null" {
		l.tokens = append(l.tokens, Token{Type: TokNull, Value: value, Line: startLine})
	} else {
		l.tokens = append(l.tokens, Token{Type: TokIdentifier, Value: value, Line: startLine})
	}
}

func isIdentifierStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func isIdentifierChar(ch byte) bool {
	return isIdentifierStart(ch) || (ch >= '0' && ch <= '9') || ch == '-'
}

type Parser struct {
	tokens []Token
	pos    int
	file   string
	line   int
}

func NewParser(source, file string) *Parser {
	lexer := NewLexer(source)
	tokens := lexer.Tokenize()
	return &Parser{
		tokens: tokens,
		file:   file,
	}
}

func (p *Parser) peek(offset int) *Token {
	idx := p.pos + offset
	if idx < len(p.tokens) {
		return &p.tokens[idx]
	}
	return nil
}

func (p *Parser) advance() *Token {
	if p.pos < len(p.tokens) {
		tok := p.tokens[p.pos]
		p.pos++
		p.line = tok.Line
		return &tok
	}
	return nil
}

func (p *Parser) expect(tokType string) (*Token, error) {
	tok := p.peek(0)
	if tok == nil {
		return nil, &HclParseError{Message: "unexpected EOF, expected " + tokType, Line: p.line, FilePath: p.file}
	}
	if tok.Type != tokType {
		return nil, &HclParseError{Message: "expected " + tokType + ", got " + tok.Type + " (" + tok.Value + ")", Line: tok.Line, FilePath: p.file}
	}
	return p.advance(), nil
}

func (p *Parser) match(tokType string) *Token {
	tok := p.peek(0)
	if tok != nil && tok.Type == tokType {
		return p.advance()
	}
	return nil
}

func (p *Parser) skipNewlines() {
	for {
		tok := p.peek(0)
		if tok != nil && tok.Type == TokNewline {
			p.advance()
		} else {
			break
		}
	}
}

func (p *Parser) atBlockStart() bool {
	tok := p.peek(0)
	return tok != nil && tok.Type == TokIdentifier && topBlockKeywords[tok.Value]
}

func (p *Parser) Parse() (*models.HclConfig, error) {
	config := models.NewHclConfig()

	for p.pos < len(p.tokens) {
		p.skipNewlines()
		if p.atBlockStart() {
			block, err := p.parseTopBlock()
			if err != nil {
				p.skipToNextBlock()
				continue
			}
			if block != nil {
				registerBlock(config, block)
			}
		} else {
			p.advance()
		}
	}

	config.SourceFiles = append(config.SourceFiles, p.file)
	return config, nil
}

func registerBlock(config *models.HclConfig, block *models.HclBlock) {
	switch block.BlockType {
	case "resource":
		config.Resources[block.Address()] = block
	case "data":
		config.DataSources[block.Address()] = block
	case "variable":
		if len(block.Labels) > 0 {
			config.Variables[block.Labels[0]] = block
		}
	case "locals":
		for k, v := range block.Attributes {
			config.Locals[k] = v
		}
	case "output":
		if len(block.Labels) > 0 {
			config.Outputs[block.Labels[0]] = block
		}
	case "module":
		if len(block.Labels) > 0 {
			config.Modules[block.Labels[0]] = block
		}
	}
}

func (p *Parser) skipToNextBlock() {
	for p.pos < len(p.tokens) {
		tok := p.peek(0)
		if tok == nil {
			break
		}
		if tok.Type == TokIdentifier && topBlockKeywords[tok.Value] {
			break
		}
		p.advance()
	}
}

func (p *Parser) parseTopBlock() (*models.HclBlock, error) {
	tok, err := p.expect(TokIdentifier)
	if err != nil {
		return nil, err
	}
	blockType := tok.Value
	line := tok.Line

	var labels []string
	for {
		p.skipNewlines()
		next := p.peek(0)
		if next == nil {
			break
		}
		if next.Type == TokString {
			strTok := p.advance()
			labels = append(labels, unquote(strTok.Value))
		} else if next.Type == TokIdentifier {
			idTok := p.advance()
			labels = append(labels, idTok.Value)
		} else {
			break
		}
	}

	p.skipNewlines()
	_, err = p.expect(TokLBrace)
	if err != nil {
		return nil, err
	}

	attributes := make(map[string]*models.HclAttribute)
	nestedBlocks := []*models.HclBlock{}
	var forEachExpr, countExpr, provider string
	var dependsOn []string

	for {
		p.skipNewlines()
		tok := p.peek(0)
		if tok == nil || tok.Type == TokRBrace {
			p.advance()
			break
		}

		if tok.Type == TokIdentifier {
			ident := tok.Value

			if ident == "dynamic" {
				dyn, err := p.parseDynamicBlock()
				if err == nil && dyn != nil {
					nestedBlocks = append(nestedBlocks, dyn)
				}
				continue
			}

			if skipBlocks[ident] {
				p.advance()
				p.skipNewlines()
				p.skipBraceBlock()
				continue
			}

			if ident == "for_each" || ident == "count" || ident == "provider" || ident == "depends_on" {
				p.advance()
				p.skipNewlines()
				_, err := p.expect(TokEquals)
				if err != nil {
					continue
				}
				switch ident {
				case "for_each":
					forEachExpr = p.readExpression()
				case "count":
					countExpr = p.readExpression()
				case "provider":
					provider = p.readExpression()
				case "depends_on":
					dependsOn = p.parseDependsOn()
				}
				p.match(TokComma)
				continue
			}

			isNested := p.isNestedBlock()
			if isNested {
				nested, err := p.parseNestedBlock(ident)
				if err == nil {
					nested.SourceFile = p.file
					nested.SourceLine = tok.Line
					nestedBlocks = append(nestedBlocks, nested)
				}
			} else {
				p.advance()
				p.skipNewlines()
				if p.match(TokEquals) != nil {
					attr, err := p.parseAttributeValue(ident)
					if err == nil && attr != nil {
						attributes[attr.Key] = attr
					}
				}
			}
		} else {
			p.advance()
		}
	}

	return &models.HclBlock{
		BlockType:   blockType,
		Labels:      labels,
		Attributes:  attributes,
		NestedBlocks: nestedBlocks,
		SourceFile:  p.file,
		SourceLine:  line,
		ForEachExpr: forEachExpr,
		CountExpr:   countExpr,
		Provider:    provider,
		DependsOn:   dependsOn,
	}, nil
}

func (p *Parser) isNestedBlock() bool {
	save := p.pos
	p.advance()
	p.skipNewlines()
	tok := p.peek(0)
	p.pos = save
	return tok != nil && tok.Type == TokLBrace
}

func (p *Parser) parseNestedBlock(name string) (*models.HclBlock, error) {
	p.advance()
	p.skipNewlines()
	_, err := p.expect(TokLBrace)
	if err != nil {
		return nil, err
	}

	attributes := make(map[string]*models.HclAttribute)
	nestedBlocks := []*models.HclBlock{}

	for {
		p.skipNewlines()
		tok := p.peek(0)
		if tok == nil || tok.Type == TokRBrace {
			p.advance()
			break
		}

		if tok.Type == TokIdentifier {
			ident := tok.Value

			if ident == "dynamic" {
				dyn, err := p.parseDynamicBlock()
				if err == nil && dyn != nil {
					nestedBlocks = append(nestedBlocks, dyn)
				}
				continue
			}

			isNested := p.isNestedBlock()
			if isNested {
				nested, err := p.parseNestedBlock(ident)
				if err == nil {
					nestedBlocks = append(nestedBlocks, nested)
				}
			} else {
				p.advance()
				p.skipNewlines()
				if p.match(TokEquals) != nil {
					attr, err := p.parseAttributeValue(ident)
					if err == nil && attr != nil {
						attributes[attr.Key] = attr
					}
				}
			}
		} else {
			p.advance()
		}
	}

	return &models.HclBlock{
		BlockType:   name,
		Labels:      []string{},
		Attributes:  attributes,
		NestedBlocks: nestedBlocks,
	}, nil
}

func (p *Parser) parseDynamicBlock() (*models.HclBlock, error) {
	tok := p.peek(0)
	if tok == nil || tok.Value != "dynamic" {
		return nil, nil
	}

	p.advance()
	blockName := ""
	labelTok := p.peek(0)
	if labelTok != nil && labelTok.Type == TokIdentifier {
		blockName = labelTok.Value
		p.advance()
	}

	p.skipNewlines()
	_, err := p.expect(TokLBrace)
	if err != nil {
		return nil, err
	}

	attributes := make(map[string]*models.HclAttribute)
	nestedBlocks := []*models.HclBlock{}

	for {
		p.skipNewlines()
		tok := p.peek(0)
		if tok == nil || tok.Type == TokRBrace {
			p.advance()
			break
		}

		if tok.Type == TokIdentifier {
			ident := tok.Value
			isNested := p.isNestedBlock()
			if isNested {
				nested, err := p.parseNestedBlock(ident)
				if err == nil {
					nestedBlocks = append(nestedBlocks, nested)
				}
			} else {
				p.advance()
				p.skipNewlines()
				if p.match(TokEquals) != nil {
					attr, err := p.parseAttributeValue(ident)
					if err == nil && attr != nil {
						attributes[attr.Key] = attr
					}
				}
			}
		} else {
			p.advance()
		}
	}

	return &models.HclBlock{
		BlockType:   "dynamic",
		Labels:      []string{blockName},
		Attributes:  attributes,
		NestedBlocks: nestedBlocks,
		IsDynamic:   true,
	}, nil
}

func (p *Parser) parseAttributeValue(key string) (*models.HclAttribute, error) {
	tok := p.peek(0)
	if tok == nil {
		return nil, nil
	}

	switch tok.Type {
	case TokLBrace:
		value, err := p.parseObjectOrMap()
		if err != nil {
			return nil, err
		}
		refs := extractRefsFromValue(value)
		return &models.HclAttribute{
			Key:          key,
			Value:        value,
			References:   refs,
			IsExpression: false,
		}, nil

	case TokLBracket:
		value, err := p.parseList()
		if err != nil {
			return nil, err
		}
		refs := extractRefsFromValue(value)
		return &models.HclAttribute{
			Key:          key,
			Value:        value,
			References:   refs,
			IsExpression: false,
		}, nil

	case TokString:
		strTok := p.advance()
		raw := strTok.Value
		unquoted := unquote(raw)
		refs := extractRefsFromString(unquoted)
		isExpr := len(refs) > 0 || strings.Contains(raw, "${")
		isConditional := strings.Contains(unquoted, "?") && strings.Contains(unquoted, ":")
		val := interface{}(unquoted)
		if isExpr {
			val = unquoted
		}
		return &models.HclAttribute{
			Key:            key,
			Value:          val,
			IsExpression:   isExpr,
			ExpressionText: unquoted,
			References:     refs,
			IsConditional:  isConditional,
		}, nil

	case TokNumber:
		numTok := p.advance()
		var val interface{}
		if strings.Contains(numTok.Value, ".") {
			f, _ := strconv.ParseFloat(numTok.Value, 64)
			val = f
		} else {
			i, _ := strconv.ParseInt(numTok.Value, 10, 64)
			val = i
		}
		return &models.HclAttribute{Key: key, Value: val}, nil

	case TokBool:
		boolTok := p.advance()
		return &models.HclAttribute{Key: key, Value: boolTok.Value == "true"}, nil

	case TokNull:
		p.advance()
		return &models.HclAttribute{Key: key, Value: nil}, nil

	case TokIdentifier:
		idTok := p.advance()
		exprParts := []string{idTok.Value}
		refs := extractRefsFromString(idTok.Value)
		isConditional := false

		next := p.peek(0)
		if next != nil && next.Type == TokQuestion {
			isConditional = true
			for {
				nt := p.peek(0)
				if nt == nil {
					break
				}
				if nt.Type == TokComma || nt.Type == TokRBrace || nt.Type == TokRBracket || nt.Type == TokNewline {
					break
				}
				exprParts = append(exprParts, nt.Value)
				p.advance()
			}
		}

		return &models.HclAttribute{
			Key:            key,
			Value:          strings.Join(exprParts, " "),
			IsExpression:   true,
			ExpressionText: strings.Join(exprParts, " "),
			References:     refs,
			IsConditional:  isConditional,
		}, nil

	default:
		p.advance()
		return nil, nil
	}
}

func (p *Parser) parseObjectOrMap() (map[string]interface{}, error) {
	_, err := p.expect(TokLBrace)
	if err != nil {
		return nil, err
	}

	result := make(map[string]interface{})

	for {
		p.skipNewlines()
		tok := p.peek(0)
		if tok == nil || tok.Type == TokRBrace {
			p.advance()
			break
		}

		if tok.Type == TokIdentifier || tok.Type == TokString {
			key := tok.Value
			if tok.Type == TokString {
				key = unquote(key)
			}
			p.advance()
			p.skipNewlines()

			if p.match(TokEquals) != nil || p.match(TokColon) != nil {
				attr, err := p.parseAttributeValue(key)
				if err == nil && attr != nil {
					val := attr.Value
					if attr.IsExpression {
						val = attr.ExpressionText
						if val == "" {
							val = attr.Value
						}
					}
					result[key] = val
				}
			}
			p.match(TokComma)
		} else if tok.Type == TokLBrace {
			nested, err := p.parseObjectOrMap()
			if err == nil {
				result[fmt.Sprintf("_nested_%d", len(result))] = nested
			}
		} else {
			p.advance()
		}
	}

	return result, nil
}

func (p *Parser) parseList() ([]interface{}, error) {
	_, err := p.expect(TokLBracket)
	if err != nil {
		return nil, err
	}

	result := []interface{}{}

	for {
		p.skipNewlines()
		tok := p.peek(0)
		if tok == nil || tok.Type == TokRBracket {
			p.advance()
			break
		}

		switch tok.Type {
		case TokString:
			strTok := p.advance()
			result = append(result, unquote(strTok.Value))
		case TokNumber:
			numTok := p.advance()
			if strings.Contains(numTok.Value, ".") {
				f, _ := strconv.ParseFloat(numTok.Value, 64)
				result = append(result, f)
			} else {
				i, _ := strconv.ParseInt(numTok.Value, 10, 64)
				result = append(result, i)
			}
		case TokBool:
			boolTok := p.advance()
			result = append(result, boolTok.Value == "true")
		case TokLBrace:
			obj, err := p.parseObjectOrMap()
			if err == nil {
				result = append(result, obj)
			}
		case TokLBracket:
			sublist, err := p.parseList()
			if err == nil {
				result = append(result, sublist)
			}
		case TokIdentifier:
			expr := p.readExpression()
			result = append(result, expr)
		default:
			p.advance()
			continue
		}

		p.match(TokComma)
	}

	return result, nil
}

func (p *Parser) readExpression() string {
	parts := []string{}
	depthBrace := 0
	depthBracket := 0
	depthParen := 0

	for p.pos < len(p.tokens) {
		tok := p.peek(0)
		if tok == nil {
			break
		}

		if depthBrace == 0 && depthBracket == 0 && depthParen == 0 {
			if tok.Type == TokComma || tok.Type == TokNewline {
				break
			}
			if tok.Type == TokRBrace {
				break
			}
			if tok.Type == TokRBracket && depthBracket == 0 {
				break
			}
		}

		switch tok.Type {
		case TokLBrace:
			depthBrace++
		case TokRBrace:
			depthBrace--
			if depthBrace < 0 {
				goto done
			}
		case TokLBracket:
			depthBracket++
		case TokRBracket:
			depthBracket--
			if depthBracket < 0 {
				goto done
			}
		case TokLParen:
			depthParen++
		case TokRParen:
			depthParen--
			if depthParen < 0 {
				goto done
			}
		}

		parts = append(parts, tok.Value)
		p.advance()
	}
done:
	return strings.TrimSpace(strings.Join(parts, " "))
}

func (p *Parser) parseDependsOn() []string {
	_, err := p.expect(TokLBracket)
	if err != nil {
		return nil
	}

	deps := []string{}

	for {
		p.skipNewlines()
		tok := p.peek(0)
		if tok == nil || tok.Type == TokRBracket {
			p.advance()
			break
		}

		dep := p.readExpression()
		dep = strings.Trim(strings.TrimSpace(dep), "\"")
		if dep != "" {
			deps = append(deps, dep)
		}
		p.match(TokComma)
	}

	return deps
}

func (p *Parser) skipBraceBlock() {
	_, err := p.expect(TokLBrace)
	if err != nil {
		return
	}
	depth := 1
	for p.pos < len(p.tokens) {
		tok := p.advance()
		if tok == nil {
			break
		}
		if tok.Type == TokLBrace {
			depth++
		} else if tok.Type == TokRBrace {
			depth--
			if depth <= 0 {
				break
			}
		}
	}
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		inner := s[1 : len(s)-1]
		inner = strings.ReplaceAll(inner, "\\\"", "\"")
		inner = strings.ReplaceAll(inner, "\\n", "\n")
		inner = strings.ReplaceAll(inner, "\\t", "\t")
		inner = strings.ReplaceAll(inner, "\\\\", "\\")
		return inner
	}
	return s
}

var (
	refPat1 = regexp.MustCompile(`\$\{(.*?)\}`)
	refPat2 = regexp.MustCompile(`\b(var\.[a-zA-Z_][a-zA-Z0-9_.]*)\b`)
	refPat3 = regexp.MustCompile(`\b(local\.[a-zA-Z_][a-zA-Z0-9_.]*)\b`)
	refPat4 = regexp.MustCompile(`\b(data\.[a-zA-Z_][a-zA-Z0-9_.]*)\b`)
	refPat5 = regexp.MustCompile(`\b(module\.[a-zA-Z_][a-zA-Z0-9_.]*)\b`)
)

func parseReference(refStr string) models.ResourceRef {
	parts := strings.Split(refStr, ".")
	modulePath := ""
	idx := 0

	if len(parts) >= 2 && parts[0] == "module" {
		modulePath = parts[1]
		idx = 2
	}

	remaining := parts[idx:]
	refType := "resource"
	var resourceType, resourceName, attribute string

	if len(remaining) >= 1 {
		switch remaining[0] {
		case "var":
			refType = "var"
			if len(remaining) >= 2 {
				resourceName = remaining[1]
			}
		case "local":
			refType = "local"
			if len(remaining) >= 2 {
				resourceName = remaining[1]
			}
		case "data":
			refType = "data"
			resourceType = "data"
			if len(remaining) >= 3 {
				resourceName = remaining[2]
			}
			if len(remaining) > 3 {
				attribute = strings.Join(remaining[3:], ".")
			}
		default:
			if len(remaining) >= 2 {
				resourceType = remaining[0]
				resourceName = remaining[1]
				if len(remaining) > 2 {
					attribute = strings.Join(remaining[2:], ".")
				}
			}
		}
	}

	return models.ResourceRef{
		RefType:      refType,
		ModulePath:   modulePath,
		ResourceType: resourceType,
		ResourceName: resourceName,
		Attribute:    attribute,
		Raw:          refStr,
	}
}

func extractRefsFromString(s string) []models.ResourceRef {
	refs := []models.ResourceRef{}
	seen := make(map[string]bool)

	patterns := []*regexp.Regexp{refPat1, refPat2, refPat3, refPat4, refPat5}

	for _, pat := range patterns {
		matches := pat.FindAllStringSubmatch(s, -1)
		for _, match := range matches {
			refStr := match[0]
			if pat == refPat1 {
				refStr = match[1]
			}
			refStr = strings.TrimSpace(refStr)
			if refStr != "" && !seen[refStr] {
				seen[refStr] = true
				refs = append(refs, parseReference(refStr))
			}
		}
	}

	return refs
}

func extractRefsFromValue(val interface{}) []models.ResourceRef {
	refs := []models.ResourceRef{}
	seen := make(map[string]bool)

	var scan func(interface{})
	scan = func(v interface{}) {
		switch val := v.(type) {
		case string:
			for _, r := range extractRefsFromString(val) {
				if !seen[r.Raw] {
					seen[r.Raw] = true
					refs = append(refs, r)
				}
			}
		case []interface{}:
			for _, item := range val {
				scan(item)
			}
		case map[string]interface{}:
			for _, item := range val {
				scan(item)
			}
		}
	}

	scan(val)
	return refs
}

func ParseFile(filePath string) (*models.HclConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	parser := NewParser(string(data), filePath)
	return parser.Parse()
}

func ParseDir(configDir string) (*models.HclConfig, error) {
	merged := models.NewHclConfig()

	info, err := os.Stat(configDir)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		if strings.HasSuffix(configDir, ".tf") {
			cfg, err := ParseFile(configDir)
			if err != nil {
				return merged, nil
			}
			mergeConfigs(merged, cfg)
			merged.SourceFiles = append(merged.SourceFiles, configDir)
		}
		return merged, nil
	}

	err = filepath.Walk(configDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".terraform" || name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".tf") {
			cfg, err := ParseFile(path)
			if err != nil {
				return nil
			}
			mergeConfigs(merged, cfg)
		}
		return nil
	})

	return merged, err
}

func mergeConfigs(target, source *models.HclConfig) {
	for k, v := range source.Resources {
		target.Resources[k] = v
	}
	for k, v := range source.DataSources {
		target.DataSources[k] = v
	}
	for k, v := range source.Variables {
		target.Variables[k] = v
	}
	for k, v := range source.Locals {
		target.Locals[k] = v
	}
	for k, v := range source.Outputs {
		target.Outputs[k] = v
	}
	for k, v := range source.Modules {
		target.Modules[k] = v
	}
}
