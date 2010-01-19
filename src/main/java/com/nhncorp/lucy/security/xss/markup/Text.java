package com.nhncorp.lucy.security.xss.markup;

import java.io.IOException;
import java.io.Writer;

/**
 * 이 클래스는 일반 텍스트를 나타낸다. <br/>
 * 일반 텍스트라 함은 {@link Comment Comment}, {@link Element Element} 이 아닌 
 * 모든 {@link Content Content}가 그 대상이 된다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 17653 $, $Date: 2008-04-15 15:47:50 +0900 (화, 15 4 2008) $
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
		this.text = (text == null)? "" : text;
	}
	
	public void serialize(Writer writer) throws IOException {
		if (writer == null) {
			return ;
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
			}
		}
		
		if (length > pos) {
			writer.write(this.text, pos, length - pos);
		}
	}
}
