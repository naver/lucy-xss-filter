package com.nhncorp.lucy.security.xss.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import com.nhncorp.lucy.security.xss.markup.Attribute;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 18530 $, $Date: 2008-08-14 14:41:03 +0900 (목, 14 8 2008) $
 */
public final class AttributeRule {

	private String name;
	private boolean disabled;
	private List<Pattern> patterns;
	private List<Pattern> npatterns;
	
	AttributeRule(String name) {
		this.name = name;
	}
	
	AttributeRule(String name, boolean disabled) {
		this.name = name;
		this.disabled = disabled;
	}

	public String getName() {
		return (this.name == null)? "" : this.name;
	}
	
	public boolean isDisabled() {
		return this.disabled;
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

	public void checkAttributeValue(Attribute att) {
		if (att != null && !att.isMinimized()) {
			String value = att.getValue();
			if (this.patterns != null && !this.patterns.isEmpty()) {
				for (Pattern p : this.patterns) {
					if (p.matcher(value).matches()) {
						return ;
					}
				}
				att.setEnabled(false);
				return ;
			} else if (this.npatterns != null && !this.npatterns.isEmpty()) {
				for (Pattern p : this.npatterns) {
					if (p.matcher(value).find()) {
						att.setEnabled(false);
						break;
					}
				}
			}
		}
	}
	
	void setDisabled(boolean disabled) {
		this.disabled = disabled;
	}
	
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
}
