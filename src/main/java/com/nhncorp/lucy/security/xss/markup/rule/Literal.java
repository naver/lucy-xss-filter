/*
 * @(#) Literal.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup.rule;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * 
 */
class Literal extends Terminal {
	private String literal;

	public Literal(String literal) {
		this.literal = (literal == null) ? "" : literal;
	}

	public String getLiteral() {
		return this.literal;
	}

	public boolean sliceToken(Token parent, CharArraySegment input) {
		boolean isTokenized = false;
		do {
			if (input != null && input.hasRemaining() && input.startWith(this.literal)) {
				parent.appendValue(input.slice(this.literal.length()));
				isTokenized = true;
			} else {
				break;
			}
		} while (this.isRepeat());

		return isTokenized;
	}

	public int matchPos(CharArraySegment input) {
		return input.posOf(this.literal);
	}
}
