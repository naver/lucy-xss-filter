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

import com.nhncorp.lucy.security.xss.LucyXssFilter;

/**
 * 이 클래스는 코멘트를 나타낸다.
 * 즉, {@code '<!--'}으로 시작하여 {@code '-->'} 으로 끝나는 모든 Content 를 나타낸다. 
 * 
 * @author Naver Labs
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

	public void serializeNoop(Writer writer) throws IOException {
		if (writer == null) {
			return;
		}

		writer.write("<!--");

		writer.write(this.text);

		writer.write("-->");
	}

	public void serializeFilteringTagInComment(Writer writer, LucyXssFilter filter) throws IOException {

		if (writer == null) {
			return;
		}

		if (filter == null) {
			// filter가 NULL이면, 디폴트 Stirct 필터링을 한다.
			serialize(writer);
			return;
		}

		writer.write("<!--");

		filter.doFilter(text, writer);

		writer.write("-->");
	}

	public void serializeFilteringTagInComment(Writer writer, boolean isFilteringTagInCommentEnabled, LucyXssFilter commentFilter) throws IOException {

		if (isFilteringTagInCommentEnabled) {
			this.serializeFilteringTagInComment(writer, commentFilter);
		} else {
			this.serializeNoop(writer);
		}
	}

}
