package com.nhncorp.lucy.security.xss.markup;

import java.io.IOException;
import java.io.Writer;

public class Description extends Content{

	/**
	 * 이 멤버 변수는 일반 텍스트 값을 저장한다.
	 */
	protected String text;
	
	/**
	 * 특정 String 값으로 초기화하는 생성자.
	 * 
	 * @param text	String.
	 */
	public Description(String text) {
		this.text = (text == null)? "" : text;
	}
	
	@Override
	public void serialize(Writer writer) throws IOException {
		if (writer == null) {
			return ;
		} 
		
		writer.write("<");
		
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
		
		writer.write(">");
	}

}
