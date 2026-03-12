const jStrgfy = (jsonObj) => {


function jsonMapSetReplacer (_, value_)
{
  if (typeof (value_) === 'object')
  {
    if (value_ instanceof Map)
    {
      value_ = Array.from (value_);
      value_.unshift ('@Map');
    }
    else if (value_ instanceof Set)
    {
      value_ = Array.from (value_);
      value_.unshift ('@Set');
    }
    else if (Array.isArray (value_) && value_.length > 0 &&
      (value_ [0] === '@Map' || value_ [0] === '@Set' || value_ [0] === '@Array'))
    {
      value_ = value_.slice ();
      value_.unshift ('@Array');
    }
  }

  return value_;
}

return JSON.stringify(jsonObj, jsonMapSetReplacer)

}


const jParse = (jStr) => {

/**
 * Provides a `JSON.parse` reviver function that supports Map and Set object deserialization.
 *
 * Must be used to deserialize JSON data serialized using #jsonMapSetReplacer.
 */

function jsonMapSetReviver (_, value_)
{
  if (Array.isArray (value_) && value_.length > 0)
  {
    let isMap, isSet;
    if ((isMap = value_ [0] === '@Map') || (isSet = value_ [0] === '@Set') || value_ [0] === '@Array')
    {
      value_.shift ();
      if (isMap)
        value_ = new Map (value_);
      else if (isSet)
        value_ = new Set (value_);
    }
  }

  return value_;

}
try {
  return JSON.parse(jStr, jsonMapSetReviver)
  
} catch (error) {
  return false
}


}