/*
 *	Copyright 2014 Naver Corp.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *		http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 */	
package com.nhncorp.lucy.security.xss.markup.rule;

import java.util.List;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Naver Labs
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

				if ("contents".equals(parent.getName())) {
					break;
				}
			} else {
				input.pos(start);
				break;
			}
		} while (this.isRepeat());

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

	/**
	 * @return
	 * @see com.nhncorp.lucy.security.xss.markup.rule.NonTerminal#nextToken()
	 */
	@Override
	public Token nextToken(Token token, CharArraySegment input, ParsingGrammar instance) {
		throw new UnsupportedOperationException();
	}
}
