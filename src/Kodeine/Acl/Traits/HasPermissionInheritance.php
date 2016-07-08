<?php namespace Kodeine\Acl\Traits;


trait HasPermissionInheritance
{
    protected $cacheInherit;

    /*
    |----------------------------------------------------------------------
    | Permission Inheritance Trait Methods
    |----------------------------------------------------------------------
    |
    */

    public function getPermissionsInherited()
    {
        $rights = [];
        $permissions = $this->permissions;

        // ntfs permissions
        // determine if ntfs is enabled
        // then more permissive wins
        $tmp = [];
        $letNtfs = function ($alias, $slug) use (&$tmp) {
            if ( config('acl.most_permissive_wins', false) ) {
                $ntfs[$alias] = array_diff($slug, [false]);
                if ( sizeof($ntfs) > 0 ) {
                    $tmp = array_replace_recursive($tmp, $ntfs);
                }
            }
        };

        // Keep all the inherited objects in here.
        $inheritedCollection = [];

        foreach ($permissions as $row) {

            // permissions without inherit ids
            if ( is_null($row->inherit_id) || ! $row->inherit_id ) {

                // ntfs determination
                $letNtfs($row->name, $row->slug);

                // merge permissions
                $rights = array_replace_recursive($rights, [$row->name => $row->slug], $tmp);
                continue;
            }

            // Get the base object of the inherited id
            if (isset($inheritedCollection[$row->inherit_id])) {
                $inherited = $inheritedCollection[$row->inherit_id];
            } else {
                // process inherit_id recursively
                $inheritedCollection[$row->inherit_id] = $inherited = $this->getRecursiveInherit($row->inherit_id, $row->slug);
            }

            $merge = $permissions->where('name', $row->name)->lists('slug', 'name');

            // fix for l5.1 and backward compatibility.
            // lists() method should return as an array.
            $merge = $this->collectionAsArray($merge);

            // Because we can change our permissions per user, we are required to change the permission name to a
            // single-slug value.
            if (($mergeKey = key($merge)) && ($inheritKey = key($inherited)) && $mergeKey !== $inheritKey) {
                // Set the value from the $mergeKey (our own permission name)
                $merge[$inheritKey] = $merge[$mergeKey];

            }

            // replace and merge permissions
            $rights = array_replace_recursive($rights, $inherited, $merge);

            // make sure we don't unset if
            // inherited & slave permission
            // have same names
            if ( $inheritKey != $row->name )
                unset($rights[$row->name]);

        }

        return $rights;
    }

    /**
     * @param $inherit_id
     * @param $permissions
     * @return array
     */
    protected function getRecursiveInherit($inherit_id, $permissions)
    {
        // avoid infinite loops,
        // save ids temporarily.
        $avoid[] = $inherit_id;

        // ntfs permissions
        // determine if ntfs is enabled
        // then more permissive wins
        $tmp = [];
        $letNtfs = function ($slug) use (&$tmp) {
            if ( config('acl.most_permissive_wins', false) ) {
                $ntfs = array_diff($slug, [false]);
                if ( sizeof($ntfs) > 0 ) {
                    $tmp = array_replace($tmp, $ntfs);
                }
            }
        };

        // get from cache or sql.
        $inherit = $this->getInherit($inherit_id);

        if ( $inherit->exists ) {

            // ntfs determination
            $letNtfs($inherit->slug);

            // replace and merge initial permission
            $permissions = array_replace_recursive($inherit->slug, $permissions, $tmp);

            // follow along into deeper inherited permissions recursively
            while ($inherit && $inherit->inherit_id > 0 && ! is_null($inherit->inherit_id)) {

                // get inherit permission from cache or sql.
                $inherit = $this->getInherit($inherit->inherit_id);

                // ntfs determination
                $letNtfs($inherit->slug);

                // replace and merge permissions
                $permissions = array_replace_recursive($inherit->slug, $permissions, $tmp);

                // avoid getting into infinite loop
                $avoid[] = $inherit->id;
                if ( in_array($inherit->inherit_id, $avoid) ) {
                    break;
                }
            };

            return [$inherit->name => $permissions];
        }

        return $permissions;
    }

    /**
     * @param $inherit_id
     * @return bool|mixed
     */
    protected function getInherit($inherit_id)
    {
        if ( $cache = $this->hasCache($inherit_id) ) {
            return $cache;
        }

        $model = config('acl.permission', 'Kodeine\Acl\Models\Eloquent\Permission');
        $query = (new $model)->where('id', $inherit_id)->first();

        return is_object($query) ? $this->setCache($query) : false;
    }

    /**
     * @param $inherit_id
     * @return bool|mixed
     */
    protected function hasCache($inherit_id)
    {
        if ( isset($this->cacheInherit[$inherit_id]) ) {
            return $this->cacheInherit[$inherit_id];
        }

        return false;
    }

    /**
     * @param $inherit
     * @return mixed
     */
    protected function setCache($inherit)
    {
        return $this->cacheInherit[$inherit->getKey()] = $inherit;
    }

    /**
     * Parses permission id from object or array.
     *
     * @param object|array|int $permission
     * @return mixed
     */
    /*protected function parsePermissionId($permission)
    {
        if ( is_string($permission) || is_numeric($permission) ) {

            $model = config('acl.permission', 'Kodeine\Acl\Models\Eloquent\Permission');
            $key = is_numeric($permission) ? 'id' : 'name';
            $alias = (new $model)->where($key, $permission)->first();

            if ( ! is_object($alias) || ! $alias->exists ) {
                throw new \InvalidArgumentException('Specified permission ' . $key . ' does not exists.');
            }

            $permission = $alias->getKey();
        }

        $model = '\Illuminate\Database\Eloquent\Model';
        if ( is_object($permission) && $permission instanceof $model ) {
            $permission = $permission->getKey();
        }

        return (int) $permission;
    }*/

}