/*
 * @(#) CharCodeSet.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup.rule;

import java.util.BitSet;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * 
 */
class CharCodeSet extends Terminal {
	private BitSet bits;

	public CharCodeSet() {
		bits = new BitSet(0xFFFF);
	}

	public CharCodeSet(char... codes) {
		this();
		for (char code : codes) {
			this.bits.set(code);
		}
	}

	public CharCodeSet(CharArraySegment pattern) {
		this();
		this.setPattern(pattern);
	}

	public void setRange(int frcode, int tocode) {
		this.bits.set(frcode, tocode + 1);
	}

	public void set(int code) {
		this.bits.set(code);
	}

	public void flip(int code) {
		this.bits.flip(code);
	}

	public void setAll(CharCodeSet other) {
		if (other != null) {
			this.bits.or(other.bits);
		}
	}

	public void flipAll(CharCodeSet other) {
		if (other != null) {
			other.bits.flip(1, 0xFFFF);
			this.bits.and(other.bits);
		}
	}

	public void flipAll() {
		this.bits.flip(1, 0xFFFF);
	}

	private void setPattern(CharArraySegment pattern) {
		boolean reverse = false;
		boolean range = false;
		int tmp = -1;
		while (pattern != null && pattern.hasRemaining()) {
			char curr = pattern.getChar();
			if (tmp < 0 && curr == '^') {
				reverse = true;
				pattern.move();
				continue;
			} else if (tmp >= 0 && curr == '-') {
				range = true;
				pattern.move();
				continue;
			} else if (pattern.startWith("#x")) {
				int start = pattern.move(2).pos();
				int end = start;
				while (pattern.hasRemaining()) {
					char ch = pattern.getChar();
					if (CharArraySegment.isHexChar(ch)) {
						end = pattern.move().pos();
					} else {
						break;
					}
				}
				curr = CharCode.parse(pattern.subSegment(start, end).toString());
			} else {
				pattern.move(1);
			}

			if (range) {
				this.setRange(tmp, curr);
				range = false;
			} else {
				this.set(curr);
				tmp = curr;
			}
		}

		if (reverse) {
			this.flipAll();
		}
	}

	public boolean matches(char code) {
		return this.bits.get(code);
	}

	// attValue를 위한 Customizing 로직
	private boolean matches(CharArraySegment input) {
		char code = input.getChar();

		if (input.length() > input.pos() + 1) {
			char next = input.charAt(input.pos() + 1);
			if (code == '<' && (next == '\'' || next == '"' || next == '<' || next == 0x20 || next == 0x9 || next == 0xD || next == 0xA)) {
				return true;
			}
		}

		return this.matches(code);
	}

	public boolean sliceToken(Token parent, CharArraySegment input) {
		boolean isTokenized = false;

		int start = -1;
		int end = -1;
		do {
			if (input == null || !input.hasRemaining()) {
				break;
			}

			if (this.matches(input.getChar()) || ("attValue".equals(parent.getName()) && this.matches(input))) {
				if (start < 0) {
					start = input.pos();
					end = input.move().pos();
				} else {
					end = input.move().pos();
				}
			} else {
				break;
			}
		} while (this.isRepeat());

		if (start >= 0 && end >= start) {
			parent.appendValue(input.subSegment(start, end));
			isTokenized = true;
		}

		return isTokenized;
	}

	public int matchPos(CharArraySegment input) {
		int pos = -1;
		for (int i = input.pos(); i < input.length(); i++) {
			if (this.matches(input.charAt(i))) {
				pos = i;
				break;
			}
		}

		return pos;
	}
}
