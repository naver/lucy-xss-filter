package com.nhncorp.lucy.security.xss.event;

import java.util.EventListener;

import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * 이 인터페이스는 Cross site scripting 코드가 삽입된 Tag 에 대하여 설정 정보 외에 별도의 필터링을 수행하기 위한
 * 메소드를 제공한다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 17653 $, $Date: 2008-04-15 15:47:50 +0900 (화, 15 4 2008) $
 */
public interface ElementListener extends EventListener {

	/**
	 * 이 메소드는 특정 {@link com.nhncorp.lucy.security.xss.markup.Element Element} 에 대해
	 * 설정 정보 외에 별도의 필터링을 수행한다.
	 * 
	 * @param e	{@link com.nhncorp.lucy.security.xss.markup.Element Element} 객체.
	 */
	public void handleElement(Element e);
}
