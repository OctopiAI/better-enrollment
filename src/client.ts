import type { BetterAuthClientPlugin } from "better-auth";
import type { betterEnrollment } from "./index";

export const betterEnrollmentClient = () => {
  return {
    id: "better-enrollment",
    $InferServerPlugin: {} as ReturnType<typeof betterEnrollment>,
    pathMethods: {
      "/invite/get": "GET",
      "/invite/check-slug": "GET",
      "/invite/list": "GET",
      "/invite/org/usage": "GET"
    }
  } satisfies BetterAuthClientPlugin;
};
