package com.nhncorp.lucy.security.xss.event;

import java.util.EventListener;

import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * 이 인터페이스는 Cross site scripting 코드가 삽입된 Tag 에 대하여 설정 정보 외에 별도의 필터링을 수행하기 위한
 * 메소드를 제공한다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22103 $, $Date: 2009-08-21 17:55:46 +0900 (금, 21 8 2009) $
 */
public interface ElementListener extends EventListener {

	/**
	 * 이 메소드는 특정 {@link com.nhncorp.lucy.security.xss.markup.Element Element} 에 대해
	 * 설정 정보 외에 별도의 필터링을 수행한다.
	 * 
	 * @param element	{@link com.nhncorp.lucy.security.xss.markup.Element Element} 객체.
	 */
	void handleElement(Element element);
}
