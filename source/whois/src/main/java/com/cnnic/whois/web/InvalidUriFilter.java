package com.cnnic.whois.web;

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.web.context.ContextLoader;

import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.controller.BaseController;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.util.WhoisUtil;
import com.cnnic.whois.view.FormatType;
import com.cnnic.whois.view.ViewResolver;
/**
 * filter invalid uri which spring can't catch
 * @author nic
 *
 */
public class InvalidUriFilter implements Filter {

	@Override
	public void destroy() {
	}
	
	@Override
	public void doFilter(ServletRequest arg0, ServletResponse arg1,
			FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) arg0;
		HttpServletResponse response = (HttpServletResponse) arg1;
		FormatType format = BaseController.getFormatType(request);
		String path = request.getRequestURI();
		QueryType queryType = QueryType.IP;
		if (StringUtils.isBlank(path)) {
			displayErrorMessage(request, response, chain, format, queryType);
			return;
		}
		String decodeUri = StringUtils.EMPTY;
		String uri = path.substring(request.getContextPath().length());
		try{
			decodeUri = WhoisUtil.urlDecode(uri);
			if(decodeUri.contains(" ")){
				displayErrorMessage(request, response, chain, format, queryType);
				return;
			}
		}catch(Exception e){
			displayErrorMessage(request, response, chain, format, queryType);
			return;
		}
		if (uri.contains("ip/::/")) {
			displayErrorMessage(request, response, chain, format, queryType);
			return;
		}
		chain.doFilter(request, response);
	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {

	}

	private void displayErrorMessage(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain,
			FormatType formatType, QueryType queryType) throws IOException, ServletException {
		ViewResolver viewResolver = (ViewResolver) ContextLoader
				.getCurrentWebApplicationContext().getBean("viewResolver");
		Map<String, Object> resultMap;
		try {
			QueryParam queryParam = BaseController.praseQueryParams(request);
			resultMap = WhoisUtil.processError(WhoisUtil.COMMENDRRORCODE,queryParam);
		} catch (QueryException e) {
			throw new ServletException("query exception:" + e);
		}
		viewResolver.writeResponse(formatType, queryType, request, response, resultMap);
	}
}