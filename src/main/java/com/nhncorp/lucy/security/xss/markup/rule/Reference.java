/*
 * @(#) Reference.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup.rule;

import java.util.List;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * 
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
				
				if("contents".equals(parent.getName())) {
					break;
				}
			} else {
				input.pos(start);
				break;
			}
		} while(this.isRepeat());
		
		return isTokenized;
	}
	
	public int matchPos(CharArraySegment input, ParsingGrammar grammar) {
		Group group = grammar.getRule(this.ref);
		
		if (group == null) {	
			return -1;
		}
		
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
