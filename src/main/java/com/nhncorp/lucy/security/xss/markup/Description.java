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
 * @author Naver Labs
 */
public class Description extends Content {
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
		this.text = (text == null) ? "" : text;
	}

	@Override
	public void serialize(Writer writer) throws IOException {
		if (writer == null) {
			return;
		}

		writer.write(this.text);
	}

}
