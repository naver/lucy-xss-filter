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

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Naver Labs
 * 
 */
class CharCode extends Terminal {
	private char code;

	public CharCode(char code) {
		this.code = code;
	}

	public char getCode() {
		return this.code;
	}

	public static char parse(String hexChars) {
		return (char)Integer.parseInt(hexChars, 16);
	}

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

	public int matchPos(CharArraySegment input) {
		return (this.code > 0xFFFF) ? input.posOf(Character.toChars(this.code)) : input.posOf((char)this.code);
	}
}
