/*
 * @(#) MarkupSaxParser.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup;

import com.nhncorp.lucy.security.xss.markup.rule.CharArraySegment;
import com.nhncorp.lucy.security.xss.markup.rule.ParsingGrammar;
import com.nhncorp.lucy.security.xss.markup.rule.Token;

/**
 * 이 클래스는 Markup이 포함된 Data({@code String or InputStream})을 {@link com.nhncorp.lucy.security.xss.markup.Content Content}의 
 * {@code Collection} 형태로 파싱하는 기능을 제공한다.
 * <br/><br/>
 * Static 클래스로 구현이 되었으며, 사용법은 다음과 같다.
 * <pre>
 * ...
 * 	Collection&lt;Content&gt; contents = MarkupParser.parse(input);
 * ...
 * </pre>
 * 
 * 파싱 과정은 파싱 룰을 통해 수행이 되며, 파싱 룰은 다음과 같다.
 * <pre>
 * 	contents	::= (comment | startTag | endTag | text)+
 *	comment		::= '&lt;!--' ([#x9-#xFFFD]* - '--&gt;') '--&gt;'
 *	startTag	::= '&lt;' tagName ([#x20#x9#xD#xA]+ attribute)* ([/#x20#x9#xD#xA]* '&gt;')?
 *	endTag		::= '&lt;/' [#x20#x9#xD#xA]* tagName [#x20#x9#xD#xA]* '&gt;'
 *	tagName		::= [^?!'"/&lt;&gt;#x20#x9#xD#xA]+
 *	attribute	::= attName ([#x20#x9#xD#xA]* '=' [#x20#x9#xD#xA]* attValue)?
 *	attName		::= [^=&lt;&gt;#x20#x9#xD#xA]+
 *	attValue	::= ('"' [^"&lt;]*  '"') | ("'" [^'&lt;]* "'") 
 *					| [^&lt;&gt;#x20#x9#xD#xA]*
 *	text		::= [^&lt;]* | ('&lt;' [^&lt;]*)
 *
 *	위의 파싱 룰정의는 XML specification 에서 정의한 EBNF Notation 을 사용하였다.
 * </pre>
 * 
 * @author Web Platform Development Team
 * 
 */
public final class MarkupSaxParser {
	private static ParsingGrammar grammar = ParsingGrammar.getInstance();

	private MarkupSaxParser() {
	}

	public static Token parse(CharArraySegment charArraySegment) {
		Token t = grammar.nextToken(charArraySegment);
		return t;
	}
}
