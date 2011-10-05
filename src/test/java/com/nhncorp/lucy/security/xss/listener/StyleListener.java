package com.nhncorp.lucy.security.xss.listener;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

public class StyleListener implements ElementListener{

	public void handleElement(Element e) {
		System.out.println("Style Listener In");
		e.removeAllContents();
		
	}

}
