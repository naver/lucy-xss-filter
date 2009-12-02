package com.nhncorp.lucy.security.xss.markup.rule;

import java.util.List;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22103 $, $Date: 2009-08-21 17:55:46 +0900 (금, 21 8 2009) $
 */
abstract class NonTerminal extends ParsingRule {
	/**
	 * 
	 * @return String
	 */
	public abstract String getRuleName();

	/**
	 * 
	 * @param parent Token
	 * @param input CharArraySegment
	 * @param grammar ParsingGrammar
	 * @return boolean
	 */
	public abstract boolean sliceTokens(Token parent, CharArraySegment input, ParsingGrammar grammar);

	/**
	 * 
	 * @param input CharArraySegment
	 * @param grammar parsingGrammar
	 * @return int
	 */
	public abstract int matchPos(CharArraySegment input, ParsingGrammar grammar);

	/**
	 * 
	 * @param grammar ParsingGrammar
	 * @return List
	 */
	public abstract List<Terminal> getFirstNonOptTerminals(ParsingGrammar grammar);
}
