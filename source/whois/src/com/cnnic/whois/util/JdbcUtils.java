package com.cnnic.whois.util;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.naming.InitialContext;
import javax.sql.DataSource;

public final class JdbcUtils {
	
	private JdbcUtils(){}
	private static DataSource ds = null;
	
	static{
		try {
			InitialContext ctx = new InitialContext();
			ds = (DataSource) ctx.lookup(WhoisUtil.JNDI_NAME);
		} catch (Exception e) {
			e.printStackTrace();
			throw new ExceptionInInitializerError("Datasource initial fail " + e);
		}
	}
	public static Connection getConnection(){
		Connection conn = null;
		try {
			conn = ds.getConnection();
		} catch (SQLException e) {
			e.printStackTrace();
			throw new RuntimeException("Get datasource fail ", e);
		}
		return conn;
	}
	
	public static void free(ResultSet rs, Statement stmt, Connection conn){
		try {
			if(rs != null)
				rs.close();
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			try {
				if(stmt != null)
					stmt.close();
			} catch (SQLException e) {
				e.printStackTrace();
			} finally {
				try {
					if(conn != null)
						conn.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
}
