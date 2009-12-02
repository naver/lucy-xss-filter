package com.nhncorp.lucy.security.xss.markup.rule;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22185 $, $Date: 2009-08-27 10:31:41 +0900 (목, 27 8 2009) $
 */
class Literal extends Terminal {
	private String literal;
	
	public Literal(String literal) {
		this.literal = (literal == null) ? "" : literal;
	}

	public String getLiteral() {
		return this.literal;
	}

	/**
	 * @param parent Token 
	 * @param input CharArraySegment
	 * @return boolean
	 */
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

	/**
	 * @param input CharArraySegment
	 * @return int
	 */
	public int matchPos(CharArraySegment input) {
		return input.posOf(this.literal);
	}
}
