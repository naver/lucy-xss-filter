/*
 * @(#) AttributeRule.java 2010. 8. 11
 *
 * Copyright 2010 NHN Corp. All rights Reserved.
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;

import com.nhncorp.lucy.security.xss.event.AttributeListener;
import com.nhncorp.lucy.security.xss.markup.Attribute;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 *
 * @author Web Platform Development Team
 *
 */
public final class AttributeRule {

	private String name;
	private boolean disabled;
	private List<Pattern> patterns;
	private List<Pattern> npatterns;
	private List<String> exceptionTagList = new ArrayList<String>();

	//Base64Decoding on the browser supporting HTML5
	private boolean base64Decoding;

	private List<AttributeListener> listeners;

	AttributeRule(String name) {
		this.name = name;
	}

	AttributeRule(String name, boolean disabled) {
		this.name = name;
		this.disabled = disabled;
	}

	public String getName() {
		return (this.name == null) ? "" : this.name;
	}

	public boolean isDisabled() {
		return this.disabled;
	}

	//Base64Decoding
	public boolean isBase64Decoding() {
		return this.base64Decoding;
	}

	public List<Pattern> getAllowedPatterns() {
		return Collections.unmodifiableList(this.patterns);
	}

	public List<Pattern> getNotAllowedPatterns() {
		return Collections.unmodifiableList(this.npatterns);
	}

	public void checkDisabled(Attribute att) {
		if (this.disabled) {
			att.setEnabled(false);
		}
	}

	private String decodeWithBase64(String originalValue) {
		String[] value = originalValue.split(",");

		if (value[0].endsWith("base64")) {
			byte[] decodedValue = Base64.decodeBase64(value[1]);
			return new String(decodedValue);
		}

		return originalValue;
	}

	/**
	 * attribute value가 whitelist를 위반하는지 검사한다.
	 *
	 * @param att {@link Attribute}
	 */
	public void checkAttributeValue(Attribute att) {
		if (att != null && !att.isMinimized()) {
			String value = att.getValue();

			if (this.isBase64Decoding()) {
				value = this.decodeWithBase64(value);
			}
			
			boolean isPatternsExist = this.patterns != null && !this.patterns.isEmpty();
			boolean isNPatternsExist = this.npatterns != null && !this.npatterns.isEmpty();
			

			if(isPatternsExist && isNPatternsExist) {
				for (Pattern p : this.npatterns) {
					if (p.matcher(value).find()) {
						att.setEnabled(false);
						break;
					}
				}
				
				for (Pattern p : this.patterns) {
					if (p.matcher(value).matches()) {
						att.setEnabled(true);
						break;
					}
				}
				
			} else {
				if (isPatternsExist) {
					for (Pattern p : this.patterns) {
						if (p.matcher(value).matches()) {
							return;
						}
					}
					att.setEnabled(false);
					return;
				} else if (isNPatternsExist) {
					for (Pattern p : this.npatterns) {
						if (p.matcher(value).find()) {
							att.setEnabled(false);
							break;
						}
					}
				}
			}
		}
	}

	void setDisabled(boolean disabled) {
		this.disabled = disabled;
	}

	//Base64Decoding
	void setBase64Decoding(boolean base64Decoding) {
		this.base64Decoding = base64Decoding;
	}

	/**
	 * WhiteList에 AllowedPatterns으로 정의된 regex를 compile해patterns에추가한다.
	 *
	 * @param regex {@link String}
	 */
	void addAllowedPattern(String regex) {
		if (regex != null) {
			if (this.patterns == null) {
				this.patterns = new ArrayList<Pattern>();
			}

			this.patterns.add(Pattern.compile(regex));
		}
	}

	void addAllowedPatters(Collection<String> regexes) {
		if (regexes != null && !regexes.isEmpty()) {
			for (String regex : regexes) {
				this.addAllowedPattern(regex);
			}
		}
	}

	/**
	 * WhiteList에 NotAllowedPatterns으로 정의된 regex를 compile해서 npatterns에 추가한다.
	 *
	 * @param regex {@link String}
	 */
	void addNotAllowedPattern(String regex) {
		if (regex != null) {
			if (this.npatterns == null) {
				this.npatterns = new ArrayList<Pattern>();
			}

			this.npatterns.add(Pattern.compile(regex));
		}
	}

	void addNotAllowedPatterns(Collection<String> regexes) {
		if (regexes != null && !regexes.isEmpty()) {
			for (String regex : regexes) {
				this.addNotAllowedPattern(regex);
			}
		}
	}

	public void executeListener(Attribute att) {
		if (this.listeners != null && !this.listeners.isEmpty()) {
			for (AttributeListener l : this.listeners) {
				l.handleAttribute(att);
			}
		}
	}

	void addListener(AttributeListener l) {
		if (l != null) {
			if (this.listeners == null) {
				this.listeners = new ArrayList<AttributeListener>();
			}

			this.listeners.add(l);
		}
	}

	public List<AttributeListener> getListeners() {
		return Collections.unmodifiableList(this.listeners);
	}
	
	public void addExceptionTag(String exceptionTag) {
		exceptionTagList.add(exceptionTag);
	}
	
	public List<String> getExceptionTagList() {
		return exceptionTagList;
	}
}
