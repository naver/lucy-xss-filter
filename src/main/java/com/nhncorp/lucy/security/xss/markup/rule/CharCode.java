package com.nhncorp.lucy.security.xss.markup.rule;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22185 $, $Date: 2009-08-27 10:31:41 +0900 (목, 27 8 2009) $
 */
class CharCode extends Terminal {
	private char code;
	
	public CharCode(char code) {
		this.code = code;
	}

	public char getCode() {
		return this.code;
	}

	/**
	 * 
	 * @param hexChars String
	 * @return char
	 */
	public static char parse(String hexChars) {
		return (char)Integer.parseInt(hexChars, 16);
	}

	/**
	 * @param parent Token
	 * @param input CharArrraySegment
	 * @return isTokenized boolean
	 */
	public boolean sliceToken(Token parent, CharArraySegment input) {
		boolean isTokenized = false;
		int start = -1;
		int end = -1;
		
		do {
			if (input != null && input.hasRemaining() && this.code == input.getChar()) {
				if (start < 0) {
					start = input.pos();
					end = input.move(1).pos();
				} else {
					end = input.move(1).pos();
				}
			} else {
				break;
			}
		
		} while (this.isRepeat());

		if (start >= 0 && end > start) {
			parent.appendValue(input.subSegment(start, end));
			isTokenized = true;
		}

		return isTokenized;
	}

	/**
	 * @param input CharArraysSegment
	 * @return int
	 */
	public int matchPos(CharArraySegment input) {
		return (this.code > 0xFFFF) ? input.posOf(Character.toChars(this.code)) : input.posOf((char)this.code);
	}
}
