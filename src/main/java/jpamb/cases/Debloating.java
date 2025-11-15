package jpamb.cases;

import jpamb.utils.*;
import static jpamb.utils.Tag.TagType.*;

public class Debloating {

  // Method 1: Dead code elimination - unreachable code after return
  @Case("(5) -> ok")
  @Case("(0) -> assertion error")
  @Tag({ CONDITIONAL })
  public static int deadCodeAfterReturn(int n) {
    if (n == 0) {
      assert false;
      return 0; // This return is never reached
    }
    // This code is reachable
    int result = n * 2;
    if (false) {
      // Dead code - condition is always false
      assert false;
      return -1;
    }
    return result;
  }

  // Method 2: Unused helper method - helper is defined but never called
  @Case("(3) -> ok")
  @Case("(0) -> assertion error")
  @Tag({ CALL })
  public static int unusedHelper(int n) {
    assert n > 0;
    // Helper method computeHelper is defined below but never called
    return n * 2;
  }

  private static int computeHelper(int x) {
    // This method is never actually called - can be removed during debloating
    return x * x * x;
  }

  // Method 3: Redundant checks - multiple checks for same condition
  @Case("(5) -> ok")
  @Case("(0) -> assertion error")
  @Tag({ CONDITIONAL })
  public static int redundantChecks(int n) {
    if (n == 0) {
      assert false;
      return 0;
    }
    // Redundant check - n is already known to be non-zero
    if (n != 0) {
      int result = 100 / n;
      // Another redundant check
      if (n != 0) {
        return result;
      }
    }
    return 0;
  }

  // Method 4: Unused parameter - parameter that doesn't affect outcome
  @Case("(5, 10) -> ok")
  @Case("(0, 20) -> assertion error")
  @Tag({ CONDITIONAL })
  public static int unusedParameter(int n, int unused) {
    // Parameter 'unused' is never actually used
    assert n > 0;
    return 100 / n;
    // 'unused' could be removed without changing behavior
  }

  // Method 5: Unused variables - computed but never used
  @Case("(4) -> ok")
  @Case("(0) -> assertion error")
  @Tag({ CONDITIONAL })
  public static int unusedVariables(int n) {
    assert n > 0;
    // These variables are computed but never used
    int square = n * n;
    int cube = n * n * n;
    int sum = square + cube;
    // Only 'n' is actually used
    return 100 / n;
  }

}

