package com.nhncorp.lucy.security.xss.markup.rule;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22103 $, $Date: 2009-08-21 17:55:46 +0900 (금, 21 8 2009) $
 */
abstract class ParsingRule {
	/**
	 * 
	 * @author nhn
	 *
	 */
	public enum UNARY {
		OPTION, REPEAT0, REPEAT1, ONE;

		/**
		 * Gets the value.
		 * 
		 * @param ch the ch
		 * 
		 * @return the value
		 */
		public static UNARY getValue(char ch) {
			switch (ch) {
				case '?':
					return OPTION;
				case '*':
					return REPEAT0;
				case '+':
					return REPEAT1;
				default :
			}
		
			return ONE;
		}
	}

	protected UNARY unary = UNARY.ONE;
	
	/**
	 * Gets the unary.
	 * 
	 * @return the unary
	 */
	public UNARY getUnary() {
		return this.unary;
	}

	/**
	 * Sets the unary.
	 * 
	 * @param unary the new unary
	 */
	public void setUnary(UNARY unary) {
		this.unary = unary;
	}

	/**
	 * Checks if is optional.
	 * 
	 * @return true, if is optional
	 */
	public boolean isOptional() {
		switch (unary) {
			case OPTION:
			case REPEAT0:
				return true;
			default :
		}
		
		return false;
	}

	/**
	 * Checks if is repeat.
	 * 
	 * @return true, if is repeat
	 */
	public boolean isRepeat() {
		switch (this.getUnary()) {
			case REPEAT0:
			case REPEAT1:
				return true;
			default: 
		}
		
		return false;
	}
}
