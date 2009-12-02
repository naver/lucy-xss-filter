package com.nhncorp.lucy.security.xss.markup;

import java.io.IOException;
import java.io.Writer;

/**
 * 이 클래스는 일반 텍스트를 나타낸다. <br/>
 * 일반 텍스트라 함은 {@link Comment Comment}, {@link Element Element} 이 아닌 
 * 모든 {@link Content Content}가 그 대상이 된다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22360 $, $Date: 2009-09-02 19:35:29 +0900 (수, 02 9 2009) $
 */
public class Text extends Content {

	/**
	 * 이 멤버 변수는 일반 텍스트 값을 저장한다.
	 */
	protected String text;

	/**
	 * 이 멤버 변수는 이 텍스트가 CrossCloseTag인지 여부를 저장한다.
	 */
	protected boolean isXCloseTag;

	/**
	 * 특정 String 값으로 초기화하는 생성자.
	 * 
	 * @param text	String.
	 */
	public Text(String text) {
		this.text = (text == null) ? "" : text;
	}

	/**
	 * 사용자가 입력한 HTML Tag에서 Cross Tag가 있을 때 EndTag를 Text로 처리하는 생성자
	 * isHeuristic이 true이면 EndTag를 정상 태그로 인식한다.
	 * false이면 HTML Tag를 Text로 인식한다. 
	 * @param text
	 * @param isXCloseTag
	 */
	public Text(String text, boolean isXCloseTag) {
		this.text = (text == null) ? "" : text;
		this.isXCloseTag = isXCloseTag;
	}

	/**
	 * @param writer Writer
	 * @throws IOException IOException
	 */
	public void serialize(Writer writer) throws IOException {
		if (writer == null) {
			return;
		}

		//CrossCloseTag이면 텍스트를 변환하지 않는다.
		if (this.isXCloseTag) {
			writer.write(this.text);
			return;
		}

		int pos = 0;
		int length = this.text.length();

		for (int i = 0; i < length; i++) {
			switch (this.text.charAt(i)) {
				case '<':
					if (i > pos) {
						writer.write(this.text, pos, i - pos);
					}

					writer.write("&lt;");
					pos = i + 1;
					break;
				case '>':
					if (i > pos) {
						writer.write(this.text, pos, i - pos);
					}

					writer.write("&gt;");
					pos = i + 1;
					break;
				default:
			}
		}

		if (length > pos) {
			writer.write(this.text, pos, length - pos);
		}
	}
}
