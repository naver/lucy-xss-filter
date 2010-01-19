package com.nhncorp.lucy.security.xss.markup.rule;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 17653 $, $Date: 2008-04-15 15:47:50 +0900 (화, 15 4 2008) $
 */
abstract class ParsingRule {

	public enum UNARY {
		OPTION,	REPEAT0, REPEAT1, ONE;

		public static UNARY getValue(char ch) {
			switch (ch) {
			case '?':
				return OPTION;
			case '*':
				return REPEAT0;
			case '+':
				return REPEAT1;
			}
			return ONE;
		}
	}


	protected UNARY unary = UNARY.ONE;


	public UNARY getUnary() {
		return this.unary;
	}

	public void setUnary(UNARY unary) {
		this.unary = unary;
	}

	public boolean isOptional() {
		switch (unary) {
		case OPTION :
		case REPEAT0 :
			return true;
		}
		return false;
	}

	public boolean isRepeat() {
		switch (this.getUnary()) {
			case REPEAT0 :
			case REPEAT1 :
				return true;
		}
		return false;
	}
}
