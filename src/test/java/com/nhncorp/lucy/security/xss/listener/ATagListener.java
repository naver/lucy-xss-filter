package com.nhncorp.lucy.security.xss.listener;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

public class ATagListener implements ElementListener{

	public void handleElement(Element e) {
		
		String styleValue = e.getAttributeValue("style");
		
		System.out.println(styleValue);
		
		if (styleValue.contains("fixed")) {
			
			boolean result = e.removeAllAttributes();
			e.putAttribute("href", "http");
			e.putAttribute("style", "color");
		}
		
	}
}
