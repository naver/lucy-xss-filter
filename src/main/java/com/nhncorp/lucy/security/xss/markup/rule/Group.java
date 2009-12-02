package com.nhncorp.lucy.security.xss.markup.rule;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22185 $, $Date: 2009-08-27 10:31:41 +0900 (목, 27 8 2009) $
 */
class Group extends NonTerminal {
	/**
	 * OPERATOR
	 * @author nhn
	 *
	 */
	public enum OPERATOR {
		OR, MINUS;
		/**
		 * 
		 * @param ch char
		 * @return OR | MINUS | null OPERATOR
		 */
		public static OPERATOR getValue(char ch) {
			switch (ch) {
				case '|':
					return OR;
				case '-':
					return MINUS;
				default :
			}

			return null;
		}
	}

	private String name;
	private OPERATOR op;
	private List<ParsingRule> rules;
	
	public Group() {
		this.rules = new ArrayList<ParsingRule>();
	}

	public Group(String name) {
		this();
		this.name = name;
	}

	@Override
	public String getRuleName() {
		return (this.name == null) ? "" : this.name;
	}

	public OPERATOR getOperator() {
		return this.op;
	}

	public void setOperator(OPERATOR op) {
		this.op = op;
	}

	/**
	 * 
	 * @return boolean
	 */
	public boolean hasOrOperation() {
		return this.op != null && this.op == OPERATOR.OR;
	}

	/**
	 * 
	 * @return boolean
	 */
	public boolean hasMinusOperation() {
		return this.op != null && this.op == OPERATOR.MINUS;
	}

	public int getRuleCount() {
		return this.rules.size();
	}

	/**
	 * 
	 * @param rule ParsingRule
	 */
	public void add(ParsingRule rule) {
		this.rules.add(rule);
	}

	/**
	 * 
	 * @param rules Collection
	 */
	public void addAll(Collection<? extends ParsingRule> rules) {
		if (rules == null) {
			return;
		}

		this.rules.addAll(rules);
	}

	/**
	 * 
	 * @param index int
	 * @return ParsingRule
	 */
	public ParsingRule get(int index) {
		return this.rules.get(index);
	}

	public List<ParsingRule> getAll() {
		return this.rules;
	}

	/**
	 * 
	 * @param rule ParsingRule
	 */
	public void remove(ParsingRule rule) {
		this.rules.remove(rule);
	}

	/**
	 * @param parent Token
	 * @param input CharArraySegment
	 * @param grammar ParsingGrammar
	 * @return inTokenized boolean
	 */
	public boolean sliceTokens(Token parent, CharArraySegment input, ParsingGrammar grammar) {
		boolean isTokenized = false;

		int start = input.pos();
		
		do {
			Token token = new Token(parent.getName());

			if (this.sliceToken(token, input, grammar)) {
				parent.addChild(token);

				isTokenized = true;
				start = input.pos();
			} else {
				input.pos(start);
				break;
			}
		
		} while (this.isRepeat());

		return isTokenized;
	}

	/**
	 * 
	 * @param parent Token
	 * @param input CharArraySegment
	 * @param grammar ParsingGrammar
	 * @return isTokenized boolean
	 */
	boolean sliceToken(Token parent, CharArraySegment input, ParsingGrammar grammar) {
		boolean isTokenized = false;

		if (input == null || !input.hasRemaining()) {
			return isTokenized;
		}

		if (this.hasOrOperation()) {
			for (ParsingRule rule : this.getAll()) {
				isTokenized = this.sliceTokenByRule(parent, rule, input, grammar);

				if (isTokenized) {
					break;
				}
			}
		} else if (this.hasMinusOperation()) {
			ParsingRule left = this.get(0);
			ParsingRule right = this.get(1);

			int pos = -1;
			
			if (right instanceof NonTerminal) {
				pos = NonTerminal.class.cast(right).matchPos(input, grammar);
			} else {
				pos = Terminal.class.cast(right).matchPos(input);
			}

			if (pos >= input.pos()) {
				CharArraySegment segment = input.subSegment(input.pos(), pos);
				isTokenized = this.sliceTokenByRule(parent, left, segment, grammar);
				input.pos(input.pos() + segment.pos());
			} else {
				isTokenized = this.sliceTokenByRule(parent, left, input, grammar);
			}
		} else {
			boolean flag = false;
		
			for (int i = 0; i < this.getRuleCount(); i++) {
				ParsingRule rule = this.get(i);
				flag = this.sliceTokenByRule(parent, rule, input, grammar);
				
				if (!rule.isOptional() && !flag) {
					isTokenized = false;
					break;
				} else if (flag) {
					isTokenized = true;
				}
			}
		}

		return isTokenized;
	}

	/**
	 * @param input CharArraySegment
	 * @param grammar ParsingGrammar
	 * @return pos int
	 */
	public int matchPos(CharArraySegment input, ParsingGrammar grammar) {
		int pos = -1;

		List<Terminal> terms = this.getFirstNonOptTerminals(grammar);
		
		if (terms != null && !terms.isEmpty()) {
			for (Terminal term : terms) {
				int tmp = term.matchPos(input);

				if (tmp >= 0 && (pos < 0 || tmp < pos)) {
					pos = tmp;
				}
			}
		}

		return pos;
	}

	/**
	 * @param grammar ParsingGrammar
	 * @return null || term List
	 */
	public List<Terminal> getFirstNonOptTerminals(ParsingGrammar grammar) {
		if (this.hasMinusOperation() || this.isOptional()) {
			return null;
		}

		List<Terminal> terms = new ArrayList<Terminal>();
		
		for (ParsingRule rule : this.getAll()) {
			if (rule.isOptional()) {
				continue;
			} else if (rule instanceof NonTerminal) {
				List<Terminal> tmp = NonTerminal.class.cast(rule).getFirstNonOptTerminals(grammar);
		
				if (tmp != null && !tmp.isEmpty()) {
					terms.addAll(tmp);
				}
			} else {
				terms.add(Terminal.class.cast(rule));
			}

			if (!this.hasOrOperation() && !terms.isEmpty()) {
				break;
			}
		}

		return terms;
	}

	/**
	 * 
	 * @param parent Token
	 * @param rule ParsingRule
	 * @param input CharArraySegment
	 * @param grammar ParsingGrammar
	 * @return isTokenized boolean
	 */
	private boolean sliceTokenByRule(Token parent, ParsingRule rule, CharArraySegment input, ParsingGrammar grammar) {
		boolean isTokenized = false;
		
		if (rule instanceof NonTerminal) {
			isTokenized = NonTerminal.class.cast(rule).sliceTokens(parent, input, grammar);
		} else {
			isTokenized = Terminal.class.cast(rule).sliceToken(parent, input);
		}

		return isTokenized;
	}
}
