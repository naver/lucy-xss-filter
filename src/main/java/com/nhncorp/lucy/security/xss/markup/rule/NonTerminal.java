/*
 * @(#) NonTerminal.java 2010. 8. 11 
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
abstract class NonTerminal extends ParsingRule {
	
	public abstract String getRuleName();

	public abstract boolean sliceTokens(Token parent, CharArraySegment input, ParsingGrammar grammar);
	
	public abstract int matchPos(CharArraySegment input, ParsingGrammar grammar);
	
	public abstract List<Terminal> getFirstNonOptTerminals(ParsingGrammar grammar);
}
