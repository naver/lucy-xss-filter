/*
 * @(#) Comment.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup;

import java.io.IOException;
import java.io.Writer;

/**
 * 이 클래스는 코멘트를 나타낸다.
 * 즉, {@code '<!--'}으로 시작하여 {@code '-->'} 으로 끝나는 모든 Content 를 나타낸다. 
 * 
 * @author Web Platform Development Team
 * 
 */
public class Comment extends Content {
	/**
	 * 이 멤버변수는 Comment 의 String 값을 나타낸다.
	 */
	protected String text;

	/**
	 * 코멘트에 해당하는 String 으로 초기화하는 생성자.
	 * 참고로, {@code '<!--', '-->'} 은 포함하지 않는다.
	 * 
	 * @param text	초기화 String.
	 */
	public Comment(String text) {
		this.text = (text == null) ? "" : text;
	}

	public void serialize(Writer writer) throws IOException {
		if (writer == null) {
			return;
		}

		writer.write("<!--");

		int pos = 0;
		int length = this.text.length();

		for (int i = 0; i < length; i++) {
			if (this.text.charAt(i) == '<') {
				if (i > pos) {
					writer.write(this.text, pos, i - pos);
				}
				writer.write("&lt;");
				pos = i + 1;
			} else if (this.text.charAt(i) == '>') {
				if (i > pos) {
					writer.write(this.text, pos, i - pos);
				}
				writer.write("&gt;");
				pos = i + 1;
			}
		}

		if (length > pos) {
			writer.write(this.text, pos, length - pos);
		}

		writer.write("-->");
	}
}
