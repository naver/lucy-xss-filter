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
package com.nhncorp.lucy.security.xss.event;

import java.util.EventListener;

import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * 이 인터페이스는 Cross site scripting 코드가 삽입된 Tag 에 대하여 설정 정보 외에 별도의 필터링을 수행하기 위한
 * 메소드를 제공한다.
 *
 * @author Naver Labs
 *
 */
public interface ElementListener extends EventListener {
	/**
	 * 이 메소드는 특정 {@link com.nhncorp.lucy.security.xss.markup.Element Element} 에 대해
	 * 설정 정보 외에 별도의 필터링을 수행한다.
	 * 
	 * @param element	{@link com.nhncorp.lucy.security.xss.markup.Element Element} 객체.
	 */
	public void handleElement(Element element);
}
