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
abstract class NonTerminal extends ParsingRule {
	public abstract String getRuleName();

	public abstract boolean sliceTokens(Token parent, CharArraySegment input, ParsingGrammar grammar);

	public abstract int matchPos(CharArraySegment input, ParsingGrammar grammar);

	public abstract List<Terminal> getFirstNonOptTerminals(ParsingGrammar grammar);

	/**
	 * @param token 
	 * @param instance 
	 * @param input 
	 * @return
	 */
	public abstract Token nextToken(Token token, CharArraySegment input, ParsingGrammar instance);
}
