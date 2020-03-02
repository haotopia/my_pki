import java.sql.*;

public class Sqllink {

    public Connection con;
    public Sqllink(){
        try {
            con = conn();
        }catch (ClassNotFoundException | SQLException ex){
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }
    }
    private static Connection conn() throws ClassNotFoundException, SQLException {
        Class.forName("org.sqlite.JDBC");
        String db = "C://Users//lflx1//IdeaProjects//CPK//dbs//cpkDB.db";
        Connection con = DriverManager.getConnection("jdbc:sqlite:"+db);
        return con;

    }

}
