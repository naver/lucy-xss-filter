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

import java.util.ArrayList;
import java.util.List;

/**
 * 이 클래스는 하나의 토큰을 나타내며, Tree Node 형태로 하위에 Token 들을 유지 하고 있다.
 * 각각의 토큰은 이름과 하위 토큰들로 구성된다.
 *
 * @author Naver Labs
 *
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

	void setValue(CharArraySegment value) {
		this.value = value;
		if (value == null && this.children != null) {
			this.children.clear();
			this.children = null;
		}
	}

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
	 * @throws IndexOutOfBoundsException	Index 값이 해당 범위를 벗어 날때 발생.
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
		for (Token token : this.children) {
			if (token.getName().equals(name)) {
				child = token;
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
		for (Token token : this.children) {
			if (token.getName().equals(name)) {
				list = (list == null) ? new ArrayList<Token>() : list;
				list.add(token);
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
	 */
	@Override
	public String toString() {
		return this.toString(0);
	}

	private String toString(int level) {
		StringBuffer indentSb = new StringBuffer();

		for (int i = 0; i < level; i++) {
			indentSb.append("\t");
		}

		StringBuffer buffer = new StringBuffer(String.format("%s%s : [%s]", indentSb.toString(), this.getName(), this.getText()));
		if (this.getChildCount() > 0) {
			for (Token child : this.getChildren()) {
				buffer.append("\n");
				buffer.append(child.toString(level + 1));
			}
		}

		return buffer.toString();
	}
}
