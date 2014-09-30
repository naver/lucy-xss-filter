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
package com.nhncorp.lucy.security.xss.markup;

import java.io.IOException;
import java.io.Writer;

/**
 * 이 클래스는 일반 텍스트를 나타낸다. <br/>
 * 일반 텍스트라 함은 {@link Comment Comment}, {@link Element Element} 이 아닌 
 * 모든 {@link Content Content}가 그 대상이 된다.
 * 
 * @author Naver Labs
 * 
 */
public class Text extends Content {
	/**
	 * 이 멤버 변수는 일반 텍스트 값을 저장한다.
	 */
	protected String text;

	/**
	 * 특정 String 값으로 초기화하는 생성자.
	 * 
	 * @param text	String.
	 */
	public Text(String text) {
		this.text = (text == null) ? "" : text;
	}

	public void serialize(Writer writer) throws IOException {
		if (writer == null) {
			return;
		}

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
	}
}
