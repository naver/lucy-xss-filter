package com.nhncorp.lucy.security.xss.listener;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

public class IEHackExtensionListener implements ElementListener {

	public void handleElement(Element e) {
		// TODO Auto-generated method stub
		e.removeAllContents();
		e.setName("<!--[if mso]>");
	}

}
