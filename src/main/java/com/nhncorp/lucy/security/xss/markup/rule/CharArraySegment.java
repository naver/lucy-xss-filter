package com.nhncorp.lucy.security.xss.markup.rule;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22103 $, $Date: 2009-08-21 17:55:46 +0900 (금, 21 8 2009) $
 */
final class CharArraySegment {
	private char[] array;
	private int offset;
	private int count;
	private int pos;
	
	/**
	 * Instantiates a new char array segment.
	 * 
	 * @param array the array
	 * @param offset the offset
	 * @param count the count
	 */
	public CharArraySegment(char[] array, int offset, int count) {
		if (offset >= array.length || count < 0) {
			throw new IndexOutOfBoundsException();
		}

		this.array = array;
		this.offset = offset;
		this.count = (count > array.length - offset) ? array.length - offset : count;
	}

	/**
	 * Instantiates a new char array segment.
	 * 
	 * @param array the array
	 */
	public CharArraySegment(char[] array) {
		this(array, 0, array.length);
	}

	/**
	 * Instantiates a new char array segment.
	 * 
	 * @param str the str
	 */
	public CharArraySegment(String str) {
		this(str.toCharArray());
	}

	/**
	 * Gets the array.
	 * 
	 * @return the array
	 */
	public char[] getArray() {
		return this.array;
	}

	/**
	 * Equals array.
	 * 
	 * @param other the other
	 * 
	 * @return true, if successful
	 */
	public boolean equalsArray(CharArraySegment other) {
		return (other != null && this.array != null && this.array == other.array);
	}

	/**
	 * Index.
	 * 
	 * @param pos the pos
	 * 
	 * @return the int
	 */
	public int index(int pos) {
		return this.offset + pos;
	}

	/**
	 * Index.
	 * 
	 * @return the int
	 */
	public int index() {
		return this.offset + this.pos;
	}

	/**
	 * Length.
	 * 
	 * @return the int
	 */
	public int length() {
		return this.count;
	}

	/**
	 * Pos.
	 * 
	 * @return the int
	 */
	public int pos() {
		return this.pos;
	}

	/**
	 * Pos.
	 * 
	 * @param newPos the new pos
	 * 
	 * @return the char array segment
	 */
	public CharArraySegment pos(int newPos) {
		this.pos = newPos;
		return this;
	}

	/**
	 * Move.
	 * 
	 * @return the char array segment
	 */
	public CharArraySegment move() {
		this.pos++;
		return this;
	}

	/**
	 * Move.
	 * 
	 * @param size the size
	 * 
	 * @return the char array segment
	 */
	public CharArraySegment move(int size) {
		this.pos += size;
		return this;
	}

	/**
	 * Pos of.
	 * 
	 * @param cs the cs
	 * 
	 * @return the int
	 */
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

	/**
	 * Pos of.
	 * 
	 * @param str the str
	 * 
	 * @return the int
	 */
	public int posOf(String str) {
		return this.posOf(str.toCharArray());
	}

	/**
	 * Last pos of.
	 * 
	 * @param cs the cs
	 * 
	 * @return the int
	 */
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

	/**
	 * Last pos of.
	 * 
	 * @param str the str
	 * 
	 * @return the int
	 */
	public int lastPosOf(String str) {
		return this.lastPosOf(str.toCharArray());
	}

	/**
	 * Checks for remaining.
	 * 
	 * @return true, if successful
	 */
	public boolean hasRemaining() {
		return this.count > this.pos;
	}

	/**
	 * Gets the char.
	 * 
	 * @return the char
	 */
	public char getChar() {
		return this.array[this.index(this.pos())];
	}

	/**
	 * Char at.
	 * 
	 * @param pos the pos
	 * 
	 * @return the char
	 */
	public char charAt(int pos) {
		return this.array[this.index(pos)];
	}

	/**
	 * 
	 * @param start int
	 * @param end int
	 * @return CharArraySegment
	 */
	public CharArraySegment subSegment(int start, int end) {
		int offset = this.index(start);
		int count = end - start;

		return new CharArraySegment(this.array, offset, count);
	}

	/**
	 * 
	 * @param start int
	 * @return CharArraySegment
	 */
	public CharArraySegment subSegment(int start) {
		return new CharArraySegment(this.array, this.index(start), this.length() - start);
	}

	/**
	 * 
	 * @return CharArraySegment
	 */
	public CharArraySegment subSegment() {
		return new CharArraySegment(this.array, this.index(this.pos()), this.length() - this.pos());
	}

	/**
	 * 
	 * @param count int
	 * @return CharArraySegment
	 */
	public CharArraySegment slice(int count) {
		CharArraySegment segment = new CharArraySegment(this.array, this.index(), count);
		this.move(count);
		return segment;
	}

	/**
	 * 
	 * @return CharArraySegment
	 */
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

	/**
	 * 
	 * @param pos int
	 * @param prefix char...
	 * @return boolean
	 */
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

	/**
	 * 
	 * @param pos int
	 * @param prefix String
	 * @return boolean
	 */
	public boolean startAt(int pos, String prefix) {
		return this.startAt(pos, prefix.toCharArray());
	}

	/**
	 * 
	 * @param prefix char...
	 * @return boolean
	 */
	public boolean startWith(char... prefix) {
		return this.startAt(this.pos, prefix);
	}

	/**
	 * 
	 * @param prefix String
	 * @return boolean
	 */
	public boolean startWith(String prefix) {
		return this.startAt(this.pos, prefix.toCharArray());
	}

	/**
	 * 
	 * @param other CharArraySegment
	 * @return this CharArraySegment
	 */
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

	/**
	 * 
	 * @param ch char
	 * @return boolean
	 */
	public static boolean isHexChar(char ch) {
		if ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return true;
		}

		return false;
	}

	/**
	 * toString
	 * @return String
	 */
	@Override
	public String toString() {
		return new String(this.array, this.offset, this.count);
	}
}
