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
		
		writer.write(this.text);
	}

}
