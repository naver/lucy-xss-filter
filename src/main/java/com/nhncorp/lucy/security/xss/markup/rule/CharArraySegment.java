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
public final class CharArraySegment {
	private char[] array;
	private int offset;
	private int count;
	private int pos;

	public CharArraySegment(char[] array, int offset, int count) throws IndexOutOfBoundsException {
		if (offset >= array.length || count < 0) {
			throw new IndexOutOfBoundsException();
		}

		this.array = array;
		this.offset = offset;
		this.count = (count > array.length - offset) ? array.length - offset : count;
	}

	public CharArraySegment(char[] array) {
		this(array, 0, array.length);
	}

	public CharArraySegment(String str) {
		this(str.toCharArray());
	}

	public char[] getArray() {
		return this.array;
	}

	public boolean equalsArray(CharArraySegment other) {
		return other != null && this.array == other.array;
	}

	public int index(int pos) {
		return this.offset + pos;
	}

	public int index() {
		return this.offset + this.pos;
	}

	public int length() {
		return this.count;
	}

	public int pos() {
		return this.pos;
	}

	public CharArraySegment pos(int newPos) {
		this.pos = newPos;
		return this;
	}

	public CharArraySegment move() {
		this.pos++;
		return this;
	}

	public CharArraySegment move(int size) {
		this.pos += size;
		return this;
	}

	public int posOf(char... cs) {
		if (cs == null) {
			return -1;
		}

		int pos = -1;
		for (int i = this.pos; i < this.count; i++) {
			if (this.startAt(i, cs)) {
				pos = i;
				break;
			}
		}

		return pos;
	}

	public int posOf(String str) {
		return this.posOf(str.toCharArray());
	}

	public int lastPosOf(char... cs) {
		if (cs == null) {
			return -1;
		}

		int pos = -1;
		for (int i = this.count - 1; i >= this.pos; i--) {
			if (this.startAt(i, cs)) {
				pos = i;
				break;
			}
		}

		return pos;
	}

	public int lastPosOf(String str) {
		return this.lastPosOf(str.toCharArray());
	}

	public boolean hasRemaining() {
		return this.count > this.pos;
	}

	public char getChar() {
		return this.array[this.index(this.pos())];
	}

	public char charAt(int pos) {
		return this.array[this.index(pos)];
	}

	public CharArraySegment subSegment(int start, int end) throws IndexOutOfBoundsException {
		int offset = this.index(start);
		int count = end - start;

		return new CharArraySegment(this.array, offset, count);
	}

	public CharArraySegment subSegment(int start) {
		return new CharArraySegment(this.array, this.index(start), this.length() - start);
	}

	public CharArraySegment subSegment() {
		return new CharArraySegment(this.array, this.index(this.pos()), this.length() - this.pos());
	}

	public CharArraySegment slice(int count) {
		CharArraySegment segment = new CharArraySegment(this.array, this.index(), count);
		this.move(count);
		return segment;
	}

	public CharArraySegment trim() {
		int from = 0;
		int to = this.length();

		for (int i = 0; i < to; i++) {
			char ch = this.charAt(i);
			if (ch != 0x0020 && ch != 0x0009 && ch != 0x000D && ch != 0x000A) {
				from = i;
				break;
			}
		}

		for (int i = to - 1; i > from; i--) {
			char ch = this.charAt(i);
			if (ch != 0x0020 && ch != 0x0009 && ch != 0x000D && ch != 0x000A) {
				to = i + 1;
				break;
			}
		}
		this.offset = from;
		this.count = to - from;
		this.pos = 0;

		return this;
	}

	public boolean startAt(int pos, char... prefix) {
		if (prefix == null || prefix.length > this.count - pos) {
			return false;
		}

		boolean flag = false;
		if (this.charAt(pos) == prefix[0]) {
			flag = true;
			for (int i = 1; i < prefix.length; i++) {
				if (this.charAt(pos + i) != prefix[i]) {
					flag = false;
					break;
				}
			}
		}
		return flag;
	}

	public boolean startAt(int pos, String prefix) {
		return this.startAt(pos, prefix.toCharArray());
	}

	public boolean startWith(char... prefix) {
		return this.startAt(this.pos, prefix);
	}

	public boolean startWith(String prefix) {
		return this.startAt(this.pos, prefix.toCharArray());
	}

	public CharArraySegment concate(CharArraySegment other) {
		if (!this.equalsArray(other)) {
			return this;
		}

		int start = (this.offset <= other.offset) ? this.offset : other.offset;
		int end = this.offset + this.count;
		end = (end >= other.offset + other.count) ? end : other.offset + other.count;

		this.offset = start;
		this.count = end - start;
		this.pos = 0;

		return this;
	}

	public static boolean isHexChar(char ch) {
		if ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return true;
		}
		return false;
	}

	@Override
	public String toString() {
		return new String(this.array, this.offset, this.count);
	}
}
