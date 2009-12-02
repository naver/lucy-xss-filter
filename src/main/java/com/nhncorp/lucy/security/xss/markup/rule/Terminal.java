package com.nhncorp.lucy.security.xss.markup.rule;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22103 $, $Date: 2009-08-21 17:55:46 +0900 (금, 21 8 2009) $
 */
abstract class Terminal extends ParsingRule {
	/**
	 * 
	 * @param parent Token
	 * @param input CharArraySegment
	 * @return boolean
	 */
	public abstract boolean sliceToken(Token parent, CharArraySegment input);

	/**
	 * 
	 * @param input CharArraySegment
	 * @return int
	 */
	public abstract int matchPos(CharArraySegment input);
}
