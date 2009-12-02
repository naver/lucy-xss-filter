package com.nhncorp.lucy.security.xss.markup.rule;

import java.util.List;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22185 $, $Date: 2009-08-27 10:31:41 +0900 (목, 27 8 2009) $
 */
class Reference extends NonTerminal {
	private String ref;
	
	public Reference(String ref) {
		this.ref = ref;
	}

	@Override
	public String getRuleName() {
		return this.ref;
	}

	/**
	 * {@inheritDoc}}
	 */
	public boolean sliceTokens(Token parent, CharArraySegment input, ParsingGrammar grammar) {
		boolean isTokenized = false;

		Group group = grammar.getRule(this.ref);
		int start = input.pos();
		
		do {
			Token token = new Token(this.ref);
		
			if (group != null && group.sliceToken(token, input, grammar)) {
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
	 * {@inheritDoc}}
	 */
	public int matchPos(CharArraySegment input, ParsingGrammar grammar) {
		Group group = grammar.getRule(this.ref);
		
		if (group == null) {	
			return -1;
		}

		return group.matchPos(input, grammar);
	}

	/**
	 * @param grammar ParsingGrammar
	 * @return List
	 */
	public List<Terminal> getFirstNonOptTerminals(ParsingGrammar grammar) {
		if (this.isOptional()) {
			return null;
		}

		if (grammar != null) {
			Group group = grammar.getRule(this.ref);
			
			if (group != null) {
				return group.getFirstNonOptTerminals(grammar);
			}
		}

		return null;
	}

	/**
	 * 
	 * @return String
	 */
	@Override
	public String toString() {
		return String.format("Reference(%s)", this.ref);
	}
}
