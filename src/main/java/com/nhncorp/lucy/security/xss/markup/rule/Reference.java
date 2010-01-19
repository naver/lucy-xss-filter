package com.nhncorp.lucy.security.xss.markup.rule;

import java.util.List;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 17653 $, $Date: 2008-04-15 15:47:50 +0900 (화, 15 4 2008) $
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

	public boolean sliceTokens(Token parent, CharArraySegment input, ParsingGrammar grammar) {
		boolean isTokenized = false;
		
		Group group = grammar.getRule(this.ref);
		int start = input.pos();
		do {
			Token token = new Token(this.ref);
			if (group.sliceToken(token, input, grammar)) {
				parent.addChild(token);
				isTokenized = true;
				start = input.pos();
			} else {
				input.pos(start);
				break;
			}
		} while(this.isRepeat());
		
		return isTokenized;
	}
	
	public int matchPos(CharArraySegment input, ParsingGrammar grammar) {
		Group group = grammar.getRule(this.ref);
		return group.matchPos(input, grammar);
	}
	
	public List<Terminal> getFirstNonOptTerminals(ParsingGrammar grammar) {
		if (this.isOptional()) {
			return null;
		}
		
		return grammar.getRule(this.ref).getFirstNonOptTerminals(grammar);
	}
	
	@Override
	public String toString() {
		return String.format("Reference(%s)", this.ref);
	}
}
