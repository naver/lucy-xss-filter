package com.nhncorp.lucy.security.xss.listener;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

public class IEHackExtensionListenerWithCallOfSetName implements ElementListener {

	public void handleElement(Element e) {
		e.removeAllContents();
	
		//IEHackExtensionElement는 setName 메소드를 지원하지 않는다.
		//UnsupportedOperationException 이 발생한다.
		e.setName("<!--[if mso]>");
	}

}
