//stringify Map & Set for encryption

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

//Parse Map & Set after decryption

const jParse = (jStr) => {

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
