package com.nhncorp.lucy.security.xss.markup.rule;

import java.util.ArrayList;
import java.util.List;

/**
 * 이 클래스는 하나의 토큰을 나타내며, Tree Node 형태로 하위에 Token 들을 유지 하고 있다.
 * 각각의 토큰은 이름과 하위 토큰들로 구성된다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22185 $, $Date: 2009-08-27 10:31:41 +0900 (목, 27 8 2009) $
 */
public final class Token {
	private String name;
	private CharArraySegment value;
	private ArrayList<Token> children;
	
	Token(String name) {
		this.name = name;
	}

	/**
	 * 이 메소드는 토큰 이름을 리턴한다.
	 * 
	 * @return	토큰 이름.
	 */
	public String getName() {
		return (this.name == null) ? "" : this.name;
	}

	/**
	 * 
	 * @param value CharArraySegment
	 */
	void setValue(CharArraySegment value) {
		this.value = value;
		
		if (value == null && this.children != null) {
			this.children.clear();
			this.children = null;
		}
	}

	/**
	 * 
	 * @param value CharArraySegment
	 */
	void appendValue(CharArraySegment value) {
		if (this.value == null) {
			this.value = new CharArraySegment(value.getArray(), value.index(0), value.length());
		} else {
			this.value.concate(value);
		}
	}

	CharArraySegment getValue() {
		return this.value;
	}

	/**
	 * 이 메소드는 토큰이 유지 하고 있는 String 값을 리턴한다.
	 * 
	 * @return	토큰 String.
	 */
	public String getText() {
		if (this.value == null) {
			return "";
		}
		
		return this.value.toString();
	}

	/**
	 * 
	 * @param child Token
	 */
	void addChild(Token child) {
		if (child == null || child.value == null) {
			return;
		}

		this.appendValue(child.value);
		
		if (this.children == null) {
			this.children = new ArrayList<Token>();
		}

		if (!this.getName().equals(child.getName())) {
			this.children.add(child);
		} else if (child.getChildCount() > 0) {
			this.children.addAll(child.getChildren());
		}
	}

	/**
	 * 
	 * @param children List
	 */
	void addChildren(List<Token> children) {
		if (children == null || children.isEmpty()) {
			return;
		}

		for (Token node : children) {
			this.addChild(node);
		}
	}

	/**
	 * 이 메소드는 특정 index 에 해당하는 하위 토큰을 리턴한다.
	 * 
	 * @param index	하위 토큰 index 값.
	 * @return	특정 index 에 해당하는 하위 토큰.
	 */
	public Token getChild(int index) {
		return (this.children == null) ? null : this.children.get(index);
	}

	/**
	 * 이 메소드는 특정 토큰 이름에 해당하는 첫 번째 하위 토큰을 리턴한다.
	 * 
	 * @param name	하위 토큰 이름.
	 * @return	특정 토큰 이름에 해당하는 첫 번째 하위 토큰.
	 */
	public Token getChild(String name) {
		if (this.children == null || this.children.isEmpty()) {
			return null;
		}

		Token child = null;
		
		for (Token ch : this.children) {
			if (ch.getName().equals(name)) {
				child = ch;
				break;
			}
		}

		return child;
	}

	/**
	 * 이 메소드는 모든 하위 토큰들을 리턴한다.
	 * 
	 * @return	모든 하위 토큰들이 포함된 {@code List}.
	 */
	public List<Token> getChildren() {
		return this.children;
	}

	/**
	 * 이 메소드는 특정 토큰 이름에 해당하는 하위 토큰들을 리턴한다.
	 * 
	 * @param name	하위 토큰 이름.
	 * @return	특정 토큰 이름에 해당하는 하위 토큰들이 포함된 {@code List}.
	 */
	public List<Token> getChildren(String name) {
		if (this.children == null || this.children.isEmpty()) {
			return null;
		}

		ArrayList<Token> list = null;
		
		for (Token child : this.children) {
			if (child.getName().equals(name)) {
				list = (list == null) ? new ArrayList<Token>() : list;
				list.add(child);
			}
		}

		return list;
	}

	/**
	 * 이 메소드는 모든 하위 토큰들의 갯수를 리턴한다.
	 * 
	 * @return	모든 하위 토큰들의 갯수.
	 */
	public int getChildCount() {
		return (this.children == null) ? 0 : this.children.size();
	}

	/**
	 * 이 메소드는 토큰을 Tree 형태의 String 으로 표현한다.
	 * 
	 * @return String
	 */
	@Override
	public String toString() {
		return this.toString(0);
	}

	/**
	 * 
	 * @param level int
	 * @return String
	 */
	private String toString(int level) {
		String indent = "";
		
		for (int i = 0; i < level; i++) {
			indent += "\t";
		}

		StringBuffer buffer = new StringBuffer(String.format("%s%s : [%s]", indent, this.getName(), this.getText()));
		
		if (this.getChildCount() > 0) {
			for (Token child : this.getChildren()) {
				buffer.append("\n");
				buffer.append(child.toString(level + 1));
			}
		}

		return buffer.toString();
	}
}
