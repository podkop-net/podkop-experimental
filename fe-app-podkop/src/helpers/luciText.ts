// luciText gives LuCI's own words in LuCI's translation: a button of the page is named as that
// of LuCI (an alias of _ the extraction of podkop's catalogue does not take).
export const luciText: (key: string) => string = (key) => _(key);
