/*
 * @(#)MailObjectEmbedListener.java $version 2011. 10. 31.
 *
 * Copyright 2007 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.nhncorp.lucy.security.xss.listener;

import java.util.List;

import org.apache.commons.lang.StringUtils;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * Object, Embed 태그를 처리하는 클래스
 * 
 * @author woochul.lee
 */
public class MailObjectEmbedListener implements ElementListener {
	public void handleElement(Element element) {
		String elementName = element.getName().toLowerCase(); // 대소문자 구분을 없애기 위해.
		String src = "";
		String width = "";
		String height = "";
		
		// 이곳은 embed태그를 처리하는 부분
		if ("embed".equals(elementName)) {
			src = element.getAttributeValue("src");
			width = element.getAttributeValue("width");
			height = element.getAttributeValue("height");
			
			processEmbed(element, src, width, height);
			return;
		}
		
		// 여기는 object를 처리하는 부분
		List<Element> embedList = element.getElementsByTagName("embed");
		if (embedList != null && embedList.size() > 0) {
			Element subEmbedElement = embedList.get(0);
			src = subEmbedElement.getAttributeValue("src");
			width = subEmbedElement.getAttributeValue("width");
			height = subEmbedElement.getAttributeValue("height");
			
			processEmbed(element, src, width, height);
		} else { // object안에 embed태그가 없으면 모든 속성과 하위 엘리먼트를 삭제한다.
			element.removeAllAttributes();
			element.removeAllContents();
		}
	}
	
	/**
	 * embed태그에 대한 처리는 이 함수에서 한다.
	 * 
	 * @param element
	 * @param src
	 * @param width
	 * @param height
	 */
	void processEmbed(Element element, String src, String width, String height) {
		if (!this.isWhiteUrl(src)) { // white url에 포함될 경우에만 그대로 노출
			if (StringUtils.isNotEmpty(src)) {
				src = src.replaceAll("\"", "").replaceAll("'", "");
			}

			if (StringUtils.isNotEmpty(width)) {
				width = width.replaceAll("[^0-9]", "");
			}

			if (StringUtils.isNotEmpty(height)) {
				height = height.replaceAll("[^0-9]", "");
			}

			String id = createTmpId();

			Element imgE = new Element("img");
			imgE.putAttribute("src", "");
			imgE.setClose(true);

			Element spanE = new Element("span");
			spanE.putAttribute("nid", "\"naver_embed_" + id + "\"");
			spanE.setClose(true);

			spanE.addContent(imgE);

			if (element.isStartClosed()) {
				element.setStartClose(false);
				element.setClose(true);
			}

			element.removeAllAttributes();
			element.removeAllContents();
			element.setName("a");
			element.putAttribute("href", "\"javascript:mUtil.viewEmbed('" + id + "','" + src + "','" + width + "','" + height + "');\"");
			element.addContent(spanE);
		}
	}

	boolean isWhiteUrl(String url) {
		try {
			WhiteUrlList list = WhiteUrlList.getInstance();
			if (list.contains(url)) {
				return true;
			}
		} catch (Exception e) {
			// ignore
		}
		return false;
	}

	String createTmpId() {
		int a = (int)(Math.random() * 100000);
		return String.format("%05d", a);
	}
}
