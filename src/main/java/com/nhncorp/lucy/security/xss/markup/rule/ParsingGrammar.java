/*
 * @(#) ParsingGrammar.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup.rule;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import com.nhncorp.lucy.security.xss.markup.rule.Group.OPERATOR;
import com.nhncorp.lucy.security.xss.markup.rule.ParsingRule.UNARY;

/**
 * 이 클래스는 파싱 룰를 내부적으로 유지 하고 있으며, 이러한 파싱 룰을 기반으로
 * 특정 Input String 에 대한 {@link #tokenize(String) tokenize(String)} 을 수행한다. <br/>
 * Singleton 으로 구현이 되었으며, 파싱 룰정의는 XML specification 에서 정의한 EBNF Notation 에 근거 하였다.
 * 
 * @author Web Platform Development Team
 * 
 */
public final class ParsingGrammar {
	
	private static String RULE_FILE = "markup.rule";
	private static String START_SYMBOL = "contents";
	private static String DEFINE = "::=";

	private static ParsingGrammar instance = new ParsingGrammar();
	private Map<String, Group> rules;

	private ParsingGrammar() {
		this.rules = new HashMap<String, Group>();
		
		BufferedReader reader = null;
		try {
			InputStream input = ParsingGrammar.class.getResourceAsStream(RULE_FILE);
			reader = new BufferedReader(new InputStreamReader(input));
			StringBuffer buffer = null;
			String line = null;
			while ((line = reader.readLine()) != null) {
				if (line.startsWith("//")) {
					if (buffer != null) {
						this.readNotation(buffer.toString());
						buffer = null;
					}
					continue;
				} else if (line.contains(DEFINE)) {
					if (buffer != null) {
						this.readNotation(buffer.toString());
					}
					buffer = new StringBuffer();
					buffer.append(line.trim());
				} else if (buffer != null) {
					buffer.append(line.trim());
				}
			}
			
			if (buffer != null) {
				this.readNotation(buffer.toString());
			}
		} catch (IOException ioe) { 
			// ignore
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException ioe) {
					// ignore
				}
			}
		}
	}
	
	/**
	 * 이 메소드는 Instance 를 리턴한다.
	 * 
	 * @return	instance.
	 */
	public static ParsingGrammar getInstance() {
		return instance;
	}

	Group getRule(String ruleName) {
		return this.rules.get(ruleName);
	}
	
	/**
	 * 이 메소드는 특정 Input String 에 대한 Tokenizing 을 수행한다.
	 * 
	 * @param input	Tokenizing 대상 Input String.
	 * @return	{@link Token Token} 객체.
	 */
	public Token tokenize(String input) {
		if (input == null || input.length() <= 0) {
			return null;
		}
		
		NonTerminal start = instance.getRule(START_SYMBOL);
		
		Token token = new Token(start.getRuleName());
		if (!start.sliceTokens(token, new CharArraySegment(input), instance)) {
			return null;
		}
		
		return token;
	}
	
	public Token nextToken(CharArraySegment input) {
		if (input == null || input.length() <= 0) {
			return null;
		}
		
		NonTerminal start = instance.getRule(START_SYMBOL);
		
		Token token = new Token(start.getRuleName());
		if (!start.sliceTokens(token, input, instance)) {
			return null;
		}
		
		return token;
	}
	
	private void readNotation(String notation) {
		if (!notation.contains(DEFINE)) {
			return ;
		}
		
		String[] pair = notation.split(DEFINE);
		String name = pair[0].trim();
		String exp = pair[1].trim();
		Group group = new Group(name);
		this.builRules(group, new CharArraySegment(exp.toCharArray()));
		this.rules.put(name, group);
	}
	
	private void builRules(Group parent, CharArraySegment input) {
		RuleType type = null;
		CharArraySegment segment = null;
	
		ArrayList<ParsingRule> tmp = new ArrayList<ParsingRule>();
		ParsingRule preRule = null;
		while (input.hasRemaining()) {
			type = RuleType.getType(input);	
			if (type == null) {
				input.move();
				continue;
			} else {
				segment = type.sliceFrom(input);
				if (type == RuleType.LITERAL && segment.length() == 1) {
					type = RuleType.CHARCODE;
					char code = segment.getChar();
					segment = new CharArraySegment(Integer.toHexString(code).toCharArray());					
				}
			}
			switch (type) {
				case LITERAL : {
					Literal literal = new Literal(segment.toString());
					tmp.add(literal);
					preRule = literal;
					break;
				}
				case CHARCODESET : {
					if (preRule != null && parent.hasOrOperation() && preRule instanceof CharCodeSet) {
						CharCodeSet set = CharCodeSet.class.cast(preRule);
						set.setAll(new CharCodeSet(segment));
					} else if (preRule != null && parent.hasMinusOperation() && preRule instanceof CharCodeSet) {
						CharCodeSet set = CharCodeSet.class.cast(preRule);
						set.flipAll(new CharCodeSet(segment));
					} else if (preRule != null && parent.hasOrOperation() && preRule instanceof CharCode) {
						CharCodeSet set = new CharCodeSet(segment);
						set.set(CharCode.class.cast(preRule).getCode());
						parent.remove(preRule);
						tmp.add(set);
						preRule = set;
					} else {
						CharCodeSet set = new CharCodeSet(segment);
						tmp.add(set);
						preRule = set;
					}
					break;
				}
				case CHARCODE : {
					if (preRule != null && parent.hasOrOperation() && preRule instanceof CharCodeSet) {
						CharCodeSet set = CharCodeSet.class.cast(preRule);
						set.set(CharCode.parse(segment.toString()));
					} else if (preRule != null && parent.hasMinusOperation() && preRule instanceof CharCodeSet) {
						CharCodeSet set = CharCodeSet.class.cast(preRule);
						set.flip(CharCode.parse(segment.toString()));
					} else if (preRule != null && parent.hasOrOperation() && preRule instanceof CharCode) {
						CharCodeSet set = new CharCodeSet();
						set.set(CharCode.class.cast(preRule).getCode());
						set.set(CharCode.parse(segment.toString()));
						parent.remove(preRule);
						tmp.add(set);
						preRule = set;
					} else {
						CharCode code = new CharCode(CharCode.parse(segment.toString()));
						tmp.add(code);
						preRule = code;
					}					
					break;
				}
				case UNARY : {
					UNARY unary = UNARY.getValue(segment.charAt(0));
					if (preRule != null && unary != UNARY.ONE) {
						if (preRule.isRepeat() && unary == UNARY.OPTION) {
							preRule.setUnary(UNARY.REPEAT0);
						} else {
							preRule.setUnary(unary);
						}
					}
					break;
				}
				case OPERATOR : {
					OPERATOR op = OPERATOR.getValue(segment.charAt(0));
					if (op != null) {
						if (tmp.size() > 1) {
							Group group = new Group();
							group.addAll(tmp);
							parent.add(group);
						} else {
							parent.addAll(tmp);
						}
						parent.setOperator(op);
						preRule = parent.get(parent.getRuleCount() - 1);
						tmp = new ArrayList<ParsingRule>();
					}
					break;
				}
				case GROUP : {
					Group group = new Group();
					this.builRules(group, segment);
					if (group.getRuleCount() == 1) {
						ParsingRule rule = group.get(0);
						tmp.add(rule);
						preRule = rule;
					} else {
						tmp.add(group);
						preRule = group;
					}
					break;
				}
				case REFERENCE : {
					Reference ref = new Reference(segment.toString());
					tmp.add(ref);
					preRule = ref;
					break;
				}
			}			
		}
		
		if (tmp.size() > 1 && parent.hasOrOperation()) {
			Group group = new Group();
			group.addAll(tmp);
			parent.add(group);
		} else {
			parent.addAll(tmp);
		}
		
		if (parent.getRuleCount() == 1) {
			parent.setOperator(null);
		}	
	}

	private enum RuleType {

		LITERAL {
			boolean startAt(CharArraySegment input) {
				char ch = input.getChar();
				return ch == '"' || ch == '\'';
			}
			
			CharArraySegment sliceFrom(CharArraySegment input) {
				char ch = input.getChar();
				int pos = input.move().posOf(ch);
				CharArraySegment result = input.subSegment(input.pos(), pos);
				input.move(result.length() + 1);
				return result;
			}
		}
		, 
		CHARCODESET {
			boolean startAt(CharArraySegment input) {
				return input.getChar() == '[';
			}
			
			CharArraySegment sliceFrom(CharArraySegment input) {
				int pos = input.move(1).posOf(']');
				CharArraySegment result = input.subSegment(input.pos(), pos);
				input.move(result.length() + 1);
				return result;
			}
		}
		, CHARCODE {
			boolean startAt(CharArraySegment input) {
				return input.startWith("#x");
			}
			
			CharArraySegment sliceFrom(CharArraySegment input) {
				int start = input.move(2).pos();
				int end = start;
				while (input.hasRemaining()) {
					char ch = input.getChar();					
					if (CharArraySegment.isHexChar(ch)){
						end = input.move(1).pos();						
					} else {
						break;
					}
				}

				return input.subSegment(start, end);
			}
		}
		, UNARY {
			boolean startAt(CharArraySegment input) {
				char ch = input.getChar();
				return ch == '?' || ch == '*' || ch == '+';
			}
			
			CharArraySegment sliceFrom(CharArraySegment input) {
				return input.move(1).subSegment(input.pos() -1, input.pos());
			}
		}
		, OPERATOR {
			boolean startAt(CharArraySegment input) {
				char ch = input.getChar();
				return ch == '|' || ch == '-';
			}
			
			CharArraySegment sliceFrom(CharArraySegment input) {
				return input.move(1).subSegment(input.pos() -1, input.pos());
			}
		}
		, GROUP {
			boolean startAt(CharArraySegment input) {
				return input.getChar() == '(';
			}
			
			CharArraySegment sliceFrom(CharArraySegment input) {
				int start = input.move(1).pos();
				int end = start;
				int depth = 0;
				while (input.hasRemaining()) {
					char ch = input.getChar();
					if (ch == '(') {
						depth++;
					} else if (ch == ')') {
						if (depth > 0) {
							depth--;
						} else {
							end = input.pos();
							input.move(1);
							break;
						}
					}
					input.move(1);
				}
				
				return input.subSegment(start, end);
			}
		}
		, REFERENCE {
			boolean startAt(CharArraySegment input) {
				return Character.isLetter(input.getChar());
			}
			
			CharArraySegment sliceFrom(CharArraySegment input) {
				int start = input.pos();
				int end = start;
				while (input.hasRemaining()) {
					if (Character.isLetterOrDigit(input.getChar())){						
						end = input.move(1).pos();
					} else {
						break;
					}
				}
				return input.subSegment(start, end);
			}
		};
		
		static RuleType getType(CharArraySegment input) {
			RuleType result = null;
			for(RuleType type : RuleType.values()) {
				if (type.startAt(input)) {
					result = type;
					break;
				}
			}
			return result;
		}
		
		abstract boolean startAt(CharArraySegment input);
		
		abstract CharArraySegment sliceFrom(CharArraySegment input);
	}
}
